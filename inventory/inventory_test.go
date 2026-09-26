package inventory

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestExampleValidates(t *testing.T) {
	inv, err := Parse([]byte(ExampleYAML))
	if err != nil {
		t.Fatal(err)
	}
	if probs := inv.Validate(); len(probs) > 0 {
		t.Fatalf("example has problems: %v", probs)
	}
	if env, _ := inv.PickEnv(""); env != "staging" {
		t.Errorf("default env: %s", env)
	}
	if _, err := inv.PickEnv("nope"); err == nil {
		t.Error("unknown env accepted")
	}
}

func TestLoadRelativeProviderFile(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "infra.yaml")
	os.WriteFile(p, []byte("project: p\nprovider: {file: cloud/cloud.yaml}\nenvironments:\n  prod:\n    hosts: {web-1: {}}\n"), 0o600)
	inv, err := Load(p)
	if err != nil {
		t.Fatal(err)
	}
	if got := inv.ProviderFile(); got != filepath.Join(dir, "cloud", "cloud.yaml") {
		t.Errorf("provider file: %s", got)
	}
	if _, err := Load(filepath.Join(dir, "missing.yaml")); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("missing: %v", err)
	}
}

func TestValidateProblems(t *testing.T) {
	cases := []struct{ yaml, want string }{
		{"environments: {}", "project is required"},
		{"project: p\nenvironments: {}", "at least one"},
		{"project: p\ndefault_env: x\nenvironments: {prod: {hosts: {a: {address: 1.1.1.1}}}}", "default_env \"x\""},
		{"project: p\nenvironments: {prod: {hosts: {a: {}}}}", "no address"},
		{"project: p\nenvironments: {prod: {hosts: {a: {address: 1.1.1.1, ssh: {via: b}}}}}", "via \"b\" is not a host"},
		{"project: p\nenvironments: {prod: {hosts: {a: {address: 1.1.1.1, ssh: {via: b}}, b: {address: 1.1.1.2, ssh: {via: a}}}}}", "cycle"},
		{"project: p\nenvironments: {prod: {hosts: {a: {address: 1.1.1.1, ssh: {address: vpn}}}}}", "vpn_address is not set"},
		{"project: p\nenvironments: {prod: {hosts: {a: {address: 1.1.1.1}}, services: {api: {hosts: [zzz]}}}}", "\"zzz\" is not a host"},
		{"project: p\nenvironments: {prod: {hosts: {a: {address: 1.1.1.1}}, services: {api: {hosts: [a], depends_on: [db]}, db: {hosts: [a], depends_on: [api]}}}}", "dependency cycle"},
		{"project: p\nenvironments: {prod: {hosts: {a: {address: 1.1.1.1, vpn_address: 10.9.0.1}}, networks: {vpn: {kind: wireguard, cidr: 10.8.0.0/24, hub: a}}}}", "outside every wireguard"},
		{"project: p\nenvironments: {prod: {hosts: {a: {address: 1.1.1.1}}, networks: {vpn: {kind: wireguard, cidr: 10.8.0.0/24}}}}", "needs hub"},
		{"project: p\nenvironments: {prod: {hosts: {a: {address: 1.1.1.1, dns: [not_a_name]}}}}", "not a fully qualified"},
		{"project: p\nenvironments: {prod: {hosts: {a: {address: 1.1.1.1, labels: {infra.x: y}}}}}", "reserved"},
		{"project: p\nenvironments: {prod: {hosts: {a: {address: 1.1.1.1}}, services: {api: {hosts: [a], ports: [{port: 70000}]}}}}", "out of range"},
		{"project: p\nenvironments: {prod: {hosts: {a: {address: 1.1.1.1}}, services: {api: {hosts: [a], expose: internet}}}}", "public, vpn or private"},
	}
	for _, c := range cases {
		inv, err := Parse([]byte(c.yaml))
		if err != nil {
			t.Errorf("%q: parse: %v", c.yaml, err)
			continue
		}
		probs := inv.Validate()
		if !strings.Contains(probs.Error(), c.want) {
			t.Errorf("%q:\n want problem containing %q\n got %v", c.yaml, c.want, probs)
		}
	}
	if _, err := Parse([]byte("project: p\nbogus: 1\n")); err == nil || !strings.Contains(err.Error(), "bogus") {
		t.Errorf("unknown field: %v", err)
	}
}

type fakeLookup struct {
	servers []Server
	err     error
	calls   int
	env     string
}

func (f *fakeLookup) Servers(_ context.Context, _ Provider, env string) ([]Server, error) {
	f.calls++
	f.env = env
	return f.servers, f.err
}

func TestResolve(t *testing.T) {
	inv, err := Parse([]byte(ExampleYAML))
	if err != nil {
		t.Fatal(err)
	}
	lk := &fakeLookup{servers: []Server{
		{Name: "hub-1", ID: 1, State: "running", Type: "cx23", Location: "fsn1", IPv4: "5.6.7.8", IPv6: "2001:db8::1"},
		{Name: "web-1", ID: 2, State: "running", Type: "cx33", Location: "fsn1", IPv4: "5.6.7.9"},
		{Name: "extra", ID: 9, State: "running", IPv4: "5.6.7.99"},
	}}
	r, err := inv.Resolve(context.Background(), "staging", lk)
	if err != nil {
		t.Fatal(err)
	}
	if lk.env != "staging" || lk.calls != 1 {
		t.Errorf("lookup env=%s calls=%d", lk.env, lk.calls)
	}
	hub := r.Hosts["hub-1"]
	if hub.Address != "5.6.7.8" || hub.AddressSource != "provider" || hub.Provider.ID != 1 || hub.IPv6 != "2001:db8::1" {
		t.Errorf("hub: %+v %+v", hub, hub.Provider)
	}
	if hub.SSH.AddressKind != AddrPublic || hub.SSH.Address != "5.6.7.8" || hub.RouteString() != "direct" {
		t.Errorf("hub ssh: %+v route %v", hub.SSH, hub.Route)
	}
	web := r.Hosts["web-1"]
	if web.SSH.AddressKind != AddrPrivate || web.SSH.Address != "10.0.1.2" || web.SSH.Via != "hub-1" {
		t.Errorf("web ssh: %+v", web.SSH)
	}
	if len(web.Route) != 2 || web.Route[0].Host != "hub-1" || web.Route[0].Address != "5.6.7.8" || web.Route[1].Address != "10.0.1.2" || !web.Reachable() {
		t.Errorf("web route: %+v", web.Route)
	}
	if web.RouteString() != "via hub-1" {
		t.Errorf("route string: %s", web.RouteString())
	}
	if strings.Join(web.Services, ",") != "api" || strings.Join(web.Networks, ",") != "internal,vpn" {
		t.Errorf("web services=%v networks=%v", web.Services, web.Networks)
	}
	db := r.Hosts["db-1"]
	if !db.Provider.Missing || db.AddressSource != "unresolved" || db.SSH.Address != "10.0.1.3" || !db.Reachable() {
		t.Errorf("db: %+v provider=%+v", db, db.Provider)
	}
	box := r.Hosts["backup-box"]
	if box.Provider != nil || box.SSH.User != "u123456" || box.SSH.Port != 23 || box.AddressSource != "inventory" {
		t.Errorf("box: %+v", box)
	}
	if strings.Join(r.ProviderOrphans, ",") != "extra" {
		t.Errorf("orphans: %v", r.ProviderOrphans)
	}
	if strings.Join(r.Networks["vpn"].Members, ",") != "hub-1,web-1" || strings.Join(r.Networks["internal"].Members, ",") != "db-1,hub-1,web-1" {
		t.Errorf("members: vpn=%v internal=%v", r.Networks["vpn"].Members, r.Networks["internal"].Members)
	}
	if r.Services["api"].Target() != "staging/api" || web.Target() != "staging/web-1" || r.Services["api"].Expose != ExposePublic {
		t.Error("targets / default expose")
	}

	// offline: provider hosts unresolved, manual ones fine, route through unresolved hub incomplete
	r, _ = inv.Resolve(context.Background(), "staging", nil)
	if r.Hosts["hub-1"].AddressSource != "unresolved" || r.Hosts["hub-1"].Reachable() {
		t.Errorf("offline hub: %+v", r.Hosts["hub-1"])
	}
	if r.Hosts["web-1"].Reachable() {
		t.Error("offline web should be unreachable through unresolved hub")
	}
	if !r.Hosts["backup-box"].Reachable() {
		t.Error("offline box should be reachable")
	}

	// provider failing is a warning
	r, err = inv.Resolve(context.Background(), "staging", &fakeLookup{err: errors.New("mycloud not found on PATH")})
	if err != nil || len(r.Warnings) != 1 || !strings.Contains(r.Warnings[0], "mycloud not found") {
		t.Errorf("provider error: err=%v warnings=%v", err, r.Warnings)
	}
}

func TestProviderCLIParsesStatus(t *testing.T) {
	var got []string
	h := &ProviderCLI{DefaultCommand: "mycloud", Run: func(_ context.Context, argv []string) ([]byte, error) {
		got = argv
		return []byte(`{"project":"p","env":"prod","resources":[
		  {"type":"server","name":"web-1","id":42,"state":"running","spec":"cx23","location":"fsn1","ipv4":"1.2.3.4","ipv6":"2a01:4f8::/64"},
		  {"type":"volume","name":"data","id":43}]}`), nil
	}}
	servers, err := h.Servers(context.Background(), Provider{File: "/x/cloud.yaml"}, "prod")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(got, " ") != "mycloud status --json --env prod --file /x/cloud.yaml" {
		t.Errorf("argv: %v", got)
	}
	if len(servers) != 1 || servers[0].ID != 42 || servers[0].IPv6 != "2a01:4f8::1" || servers[0].Type != "cx23" {
		t.Errorf("servers: %+v", servers)
	}
}
