package inventory

import (
	"bytes"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

// Problems is a list of validation findings.
type Problems []string

func (p Problems) Error() string { return strings.Join(p, "; ") }

// Load reads and validates infra.yaml. A Problems error means the file
// parsed but is inconsistent; other errors are syntax or I/O.
func Load(path string) (*Inventory, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	inv, err := Parse(b)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	inv.Path = path
	if probs := inv.Validate(); len(probs) > 0 {
		return inv, probs
	}
	return inv, nil
}

// Parse decodes the YAML strictly (unknown fields are errors) without
// validating references.
func Parse(b []byte) (*Inventory, error) {
	dec := yaml.NewDecoder(bytes.NewReader(b))
	dec.KnownFields(true)
	inv := &Inventory{}
	if err := dec.Decode(inv); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, err
		}
		return nil, err
	}
	return inv, nil
}

// Dir is the directory relative paths resolve against.
func (inv *Inventory) Dir() string {
	if inv.Path == "" {
		return "."
	}
	return filepath.Dir(inv.Path)
}

// ProviderFile returns the provider's config path, or "" when none is set.
func (inv *Inventory) ProviderFile() string {
	if inv.Provider == nil || inv.Provider.File == "" {
		return ""
	}
	f := inv.Provider.File
	if strings.HasPrefix(f, "~/") {
		if home, err := os.UserHomeDir(); err == nil {
			f = filepath.Join(home, f[2:])
		}
	}
	if !filepath.IsAbs(f) {
		f = filepath.Join(inv.Dir(), f)
	}
	return f
}

// TokenKeyFile returns the token public key path, or "".
func (inv *Inventory) TokenKeyFile() string {
	if inv.Tokens == nil || inv.Tokens.PublicKeyFile == "" {
		return ""
	}
	f := inv.Tokens.PublicKeyFile
	if strings.HasPrefix(f, "~/") || filepath.IsAbs(f) {
		return f
	}
	return filepath.Join(inv.Dir(), f)
}

// PolicyFile returns the policy file path: tokens.policy_file, else
// policy.yaml next to the inventory if present, else "".
func (inv *Inventory) PolicyFile() string {
	if inv.Tokens != nil && inv.Tokens.PolicyFile != "" {
		f := inv.Tokens.PolicyFile
		if strings.HasPrefix(f, "~/") || filepath.IsAbs(f) {
			return f
		}
		return filepath.Join(inv.Dir(), f)
	}
	p := filepath.Join(inv.Dir(), "policy.yaml")
	if _, err := os.Stat(p); err == nil {
		return p
	}
	return ""
}

// EnvNames returns the environment names sorted.
func (inv *Inventory) EnvNames() []string {
	names := make([]string, 0, len(inv.Environments))
	for n := range inv.Environments {
		names = append(names, n)
	}
	sort.Strings(names)
	return names
}

// PickEnv selects the environment: the given name, else default_env, else
// the only one.
func (inv *Inventory) PickEnv(name string) (string, error) {
	if name != "" {
		if _, ok := inv.Environments[name]; !ok {
			return "", fmt.Errorf("environment %q is not in the inventory (have: %s)", name, strings.Join(inv.EnvNames(), ", "))
		}
		return name, nil
	}
	if inv.DefaultEnv != "" {
		return inv.DefaultEnv, nil
	}
	if len(inv.Environments) == 1 {
		return inv.EnvNames()[0], nil
	}
	return "", fmt.Errorf("several environments (%s) and no default_env: pass --env", strings.Join(inv.EnvNames(), ", "))
}

// Validate checks names, references, addresses and cycles.
func (inv *Inventory) Validate() Problems {
	var p Problems
	add := func(format string, args ...any) { p = append(p, fmt.Sprintf(format, args...)) }
	if inv.Project == "" {
		add("project is required")
	} else if !ValidName(inv.Project) {
		add("project %q: lowercase letters, digits and dashes only", inv.Project)
	}
	if len(inv.Environments) == 0 {
		add("environments: at least one is required")
	}
	if inv.DefaultEnv != "" {
		if _, ok := inv.Environments[inv.DefaultEnv]; !ok {
			add("default_env %q is not an environment", inv.DefaultEnv)
		}
	}
	if inv.SSH.Port < 0 || inv.SSH.Port > 65535 {
		add("ssh.port %d out of range", inv.SSH.Port)
	}
	for _, envName := range inv.EnvNames() {
		env := inv.Environments[envName]
		if env == nil {
			add("environments.%s: empty", envName)
			continue
		}
		if !ValidName(envName) {
			add("environments.%s: lowercase letters, digits and dashes only", envName)
		}
		if env.Domain != "" && !ValidDNS(env.Domain) {
			add("environments.%s.domain %q is not a domain name", envName, env.Domain)
		}
		validateEnv(envName, env, inv, add)
	}
	return p
}

func validateEnv(envName string, env *Environment, inv *Inventory, add func(string, ...any)) {
	pfx := "environments." + envName
	// networks
	cidrs := map[string]netip.Prefix{}
	for _, n := range sortedKeys(env.Networks) {
		net := env.Networks[n]
		np := pfx + ".networks." + n
		if !ValidName(n) {
			add("%s: lowercase letters, digits and dashes only", np)
		}
		if net == nil {
			add("%s: kind is required", np)
			continue
		}
		switch net.Kind {
		case NetWireGuard:
			if net.Hub == "" {
				add("%s: wireguard network needs hub: <host>", np)
			} else if _, ok := env.Hosts[net.Hub]; !ok {
				add("%s.hub %q is not a host of %s", np, net.Hub, envName)
			}
			if net.CIDR == "" {
				add("%s: wireguard network needs cidr", np)
			}
		case NetPrivate:
			if inv.Provider == nil && net.CIDR == "" {
				add("%s: private network needs cidr (no provider to resolve it from)", np)
			}
		default:
			add("%s.kind %q: wireguard or private", np, net.Kind)
		}
		if net.CIDR != "" {
			pf, err := netip.ParsePrefix(net.CIDR)
			if err != nil {
				add("%s.cidr %q: %v", np, net.CIDR, err)
			} else {
				cidrs[n] = pf
			}
		}
	}
	// hosts
	for _, h := range sortedKeys(env.Hosts) {
		host := env.Hosts[h]
		hp := pfx + ".hosts." + h
		if !ValidName(h) {
			add("%s: lowercase letters, digits and dashes only", hp)
		}
		if host == nil {
			host = &Host{}
			env.Hosts[h] = host
		}
		if host.Provider != "" && host.Provider != ProviderNone && !ValidName(host.Provider) {
			add("%s.provider %q is not a server name", hp, host.Provider)
		}
		onProvider := host.OnProvider(inv)
		if host.Address == "" && !onProvider && host.VPNAddress == "" && host.PrivateAddress == "" {
			add("%s: no address, and not resolvable from a provider (set address, or provider: <server>)", hp)
		}
		for _, a := range []struct{ k, v string }{{"address", host.Address}, {"private_address", host.PrivateAddress}, {"vpn_address", host.VPNAddress}} {
			if a.v == "" {
				continue
			}
			if _, err := netip.ParseAddr(a.v); err != nil && a.k != "address" {
				add("%s.%s %q is not an IP address", hp, a.k, a.v)
			} else if err != nil && !ValidDNS(a.v) && net.ParseIP(a.v) == nil {
				add("%s.address %q is neither an IP nor a DNS name", hp, a.v)
			}
		}
		if host.SSH.Port < 0 || host.SSH.Port > 65535 {
			add("%s.ssh.port %d out of range", hp, host.SSH.Port)
		}
		if host.SSH.Via != "" {
			if host.SSH.Via == h {
				add("%s.ssh.via: a host cannot jump through itself", hp)
			} else if _, ok := env.Hosts[host.SSH.Via]; !ok {
				add("%s.ssh.via %q is not a host of %s", hp, host.SSH.Via, envName)
			}
		}
		switch host.SSH.Address {
		case "", AddrPublic, AddrVPN, AddrPrivate:
		default:
			add("%s.ssh.address %q: public, vpn or private", hp, host.SSH.Address)
		}
		if host.SSH.Address == AddrVPN && host.VPNAddress == "" {
			add("%s.ssh.address is vpn but vpn_address is not set", hp)
		}
		if host.SSH.Address == AddrPrivate && host.PrivateAddress == "" {
			add("%s.ssh.address is private but private_address is not set", hp)
		}
		for _, r := range host.Roles {
			if !ValidName(r) {
				add("%s.roles: %q is not a role name", hp, r)
			}
		}
		for _, d := range host.DNS {
			if !ValidDNS(d) {
				add("%s.dns: %q is not a fully qualified name", hp, d)
			}
		}
		for _, n := range host.Networks {
			if _, ok := env.Networks[n]; !ok {
				add("%s.networks: %q is not a network of %s", hp, n, envName)
			}
		}
		for k := range host.Labels {
			if strings.HasPrefix(k, "infra.") {
				add("%s.labels: %q is reserved", hp, k)
			}
		}
		// vpn address inside its network
		if host.VPNAddress != "" {
			if a, err := netip.ParseAddr(host.VPNAddress); err == nil {
				inSome, anyWG := false, false
				for n, pf := range cidrs {
					if env.Networks[n].Kind != NetWireGuard {
						continue
					}
					anyWG = true
					if pf.Contains(a) {
						inSome = true
					}
				}
				if anyWG && !inSome {
					add("%s.vpn_address %s is outside every wireguard network of %s", hp, host.VPNAddress, envName)
				}
			}
		}
	}
	// via cycles
	for _, h := range sortedKeys(env.Hosts) {
		seen := map[string]bool{h: true}
		cur := env.Hosts[h].SSH.Via
		for cur != "" {
			if seen[cur] {
				add("%s.hosts.%s.ssh.via: jump host cycle through %s", pfx, h, cur)
				break
			}
			seen[cur] = true
			next, ok := env.Hosts[cur]
			if !ok || next == nil {
				break
			}
			cur = next.SSH.Via
		}
	}
	// services
	for _, s := range sortedKeys(env.Services) {
		svc := env.Services[s]
		sp := pfx + ".services." + s
		if !ValidName(s) {
			add("%s: lowercase letters, digits and dashes only", sp)
		}
		if svc == nil {
			svc = &Service{}
			env.Services[s] = svc
		}
		if len(svc.Hosts) == 0 {
			add("%s: hosts is required (which hosts run it)", sp)
		}
		switch svc.Expose {
		case "", ExposePublic, ExposeVPN, ExposePrivate:
		default:
			add("%s.expose %q: public, vpn or private", sp, svc.Expose)
		}
		for _, h := range svc.Hosts {
			if _, ok := env.Hosts[h]; !ok {
				add("%s.hosts: %q is not a host of %s", sp, h, envName)
			}
		}
		for _, d := range svc.DependsOn {
			if d == s {
				add("%s.depends_on: a service cannot depend on itself", sp)
			} else if _, ok := env.Services[d]; !ok {
				add("%s.depends_on: %q is not a service of %s", sp, d, envName)
			}
		}
		for i, port := range svc.Ports {
			if port.Port < 1 || port.Port > 65535 {
				add("%s.ports[%d]: port %d out of range", sp, i, port.Port)
			}
			switch port.Protocol {
			case "", "tcp", "udp":
			default:
				add("%s.ports[%d].protocol %q: tcp or udp", sp, i, port.Protocol)
			}
		}
		for _, d := range svc.DNS {
			if !ValidDNS(d) {
				add("%s.dns: %q is not a fully qualified name", sp, d)
			}
		}
	}
	// dependency cycles
	state := map[string]int{}
	var visit func(string, []string)
	visit = func(s string, path []string) {
		switch state[s] {
		case 1:
			add("%s.services: dependency cycle %s -> %s", pfx, strings.Join(path, " -> "), s)
			return
		case 2:
			return
		}
		state[s] = 1
		if svc := env.Services[s]; svc != nil {
			for _, d := range svc.DependsOn {
				if _, ok := env.Services[d]; ok {
					visit(d, append(path, s))
				}
			}
		}
		state[s] = 2
	}
	for _, s := range sortedKeys(env.Services) {
		visit(s, nil)
	}
}

// OnProvider reports whether the host's address comes from the provider.
func (h *Host) OnProvider(inv *Inventory) bool {
	if h.Provider == ProviderNone {
		return false
	}
	if h.Provider != "" {
		return true
	}
	return inv.Provider != nil
}

// ProviderName returns the host's server name at the provider, or "".
func (h *Host) ProviderName(inv *Inventory, hostName string) string {
	if !h.OnProvider(inv) {
		return ""
	}
	if h.Provider != "" {
		return h.Provider
	}
	return hostName
}

func sortedKeys[V any](m map[string]V) []string {
	ks := make([]string, 0, len(m))
	for k := range m {
		ks = append(ks, k)
	}
	sort.Strings(ks)
	return ks
}
