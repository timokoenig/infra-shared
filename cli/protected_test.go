package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestProtectedEnvironment(t *testing.T) {
	dir := t.TempDir()
	inv := filepath.Join(dir, "infra.yaml")
	os.WriteFile(inv, []byte("project: acme\ndefault_env: staging\nenvironments:\n  staging:\n    hosts: {web-1: {address: 1.2.3.4}}\n  prod:\n    protected: true\n    hosts: {web-1: {address: 5.6.7.8}}\n"), 0o600)
	ran := 0
	getenv := func(confirm string) func(string) string {
		return func(k string) string {
			switch k {
			case "XDG_STATE_HOME":
				return dir
			case "INFRA_CONFIRM":
				return confirm
			}
			return ""
		}
	}
	app := func(confirm string) (*App, *bytes.Buffer) {
		var out, errb bytes.Buffer
		return &App{Name: "t", Stdout: &out, Stderr: &errb, Getenv: getenv(confirm), Commands: []Command{
			{Name: "apply", Mutating: true, Run: func(c *Ctx, _ []string) error { ran++; return nil }},
			{Name: "init", Mutating: true, Local: true, Run: func(c *Ctx, _ []string) error { ran++; return nil }},
			{Name: "plan", Run: func(c *Ctx, _ []string) error { ran++; return nil }},
		}}, &errb
	}
	a, _ := app("")
	if code := a.Main([]string{"-i", inv, "apply"}); code != 0 || ran != 1 { // default env staging: free
		t.Fatalf("staging apply: %d ran=%d", code, ran)
	}
	a, errb := app("")
	if code := a.Main([]string{"-i", inv, "-e", "prod", "apply"}); code != 3 || ran != 1 || !strings.Contains(errb.String(), "--confirm prod") {
		t.Fatalf("prod apply without confirm: %d ran=%d %s", code, ran, errb.String())
	}
	a, _ = app("")
	if code := a.Main([]string{"-i", inv, "-e", "prod", "--confirm", "prod", "apply"}); code != 0 || ran != 2 {
		t.Fatalf("prod apply with confirm: %d ran=%d", code, ran)
	}
	a, _ = app("")
	if code := a.Main([]string{"-i", inv, "-e", "prod", "--confirm", "staging", "apply"}); code != 3 || ran != 2 {
		t.Fatalf("wrong confirm: %d ran=%d", code, ran)
	}
	a, _ = app("")
	if code := a.Main([]string{"-i", inv, "-e", "prod", "plan"}); code != 0 || ran != 3 { // read-only: free
		t.Fatalf("prod plan: %d ran=%d", code, ran)
	}
	a, _ = app("")
	if code := a.Main([]string{"-i", inv, "-e", "prod", "init"}); code != 0 || ran != 4 { // local: free
		t.Fatalf("prod init: %d ran=%d", code, ran)
	}
	a, _ = app("prod")
	if code := a.Main([]string{"-i", inv, "-e", "prod", "apply"}); code != 0 || ran != 5 {
		t.Fatalf("INFRA_CONFIRM: %d ran=%d", code, ran)
	}
	a, _ = app("")
	if code := a.Main([]string{"-i", filepath.Join(dir, "missing.yaml"), "-e", "prod", "apply"}); code != 0 || ran != 6 { // no inventory: not this guard's business
		t.Fatalf("missing inventory: %d ran=%d", code, ran)
	}
}
