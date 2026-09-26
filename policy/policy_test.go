package policy

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestPolicy(t *testing.T) {
	dir := t.TempDir()
	p, err := Load(filepath.Join(dir, "none.yaml"))
	if err != nil || p.Decide("ship", "deploy", "prod/api") != Allow {
		t.Fatalf("missing file: %v %v", err, p)
	}
	f := filepath.Join(dir, "policy.yaml")
	os.WriteFile(f, []byte("deny:\n  - \"hetz:destroy *\"\n  - \"*:* prod/db-*\"\napprove:\n  - \"ship:deploy prod/*\"\n  - \"rig:apply\"\napproval_ttl: 30m\n"), 0o600)
	p, err = Load(f)
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		tool, action, target string
		want                 Decision
	}{
		{"hetz", "destroy", "prod", Deny},
		{"hetz", "apply", "prod", Allow},
		{"ship", "deploy", "prod/db-1", Deny},
		{"ship", "deploy", "prod/api", NeedsApproval},
		{"ship", "deploy", "staging/api", Allow},
		{"rig", "apply", "staging/web-1", NeedsApproval},
		{"rig", "plan", "staging/web-1", Allow},
		{"vault", "read", "prod/db-1", Deny},
	}
	for _, c := range cases {
		if got := p.Decide(c.tool, c.action, c.target); got != c.want {
			t.Errorf("%s:%s %s: want %s, got %s", c.tool, c.action, c.target, c.want, got)
		}
	}
	if p.TTL() != 30*time.Minute {
		t.Error("ttl")
	}
	os.WriteFile(f, []byte("deny: [nonsense]\n"), 0o600)
	if _, err := Load(f); err == nil {
		t.Error("bad pattern accepted")
	}
	os.WriteFile(f, []byte("bogus: 1\n"), 0o600)
	if _, err := Load(f); err == nil {
		t.Error("unknown key accepted")
	}
}
