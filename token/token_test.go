package token

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/timokoenig/infra-shared/approval"
)

func TestRoundTripAndScopes(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	now := time.Date(2026, 9, 25, 12, 0, 0, 0, time.UTC)
	tok := &Token{ID: "t1", Subject: "agent", Scopes: []string{"deploy:run staging/*", "secrets:read staging/*", "monitor:read", "inventory:*"},
		IssuedAt: now, ExpiresAt: now.Add(time.Hour)}
	s, err := Encode(tok, priv)
	if err != nil {
		t.Fatal(err)
	}
	got, err := Verify(s, pub, now.Add(10*time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		tool, action, target string
		want                 bool
	}{
		{"deploy", "run", "staging/api", true},
		{"deploy", "run", "prod/api", false},
		{"deploy", "rollback", "staging/api", false},
		{"secrets", "read", "staging/web-1", true},
		{"secrets", "write", "staging/web-1", false},
		{"monitor", "read", "", true},
		{"monitor", "read", "anything", true},
		{"inventory", "doctor", "prod", true},
		{"config", "apply", "staging/web-1", false},
	}
	for _, c := range cases {
		if got.Allows(c.tool, c.action, c.target) != c.want {
			t.Errorf("%s:%s %s: want %v", c.tool, c.action, c.target, c.want)
		}
	}
	if _, err := Verify(s, pub, now.Add(2*time.Hour)); err == nil {
		t.Error("expired token verified")
	}
	pub2, _, _ := ed25519.GenerateKey(rand.Reader)
	if _, err := Verify(s, pub2, now); err == nil {
		t.Error("wrong key verified")
	}
	if _, err := Verify(s[:len(s)-3]+"AAA", pub, now); err == nil {
		t.Error("tampered signature verified")
	}
}

func TestGuard(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	dir := t.TempDir()
	keyFile := filepath.Join(dir, "issuer.pub")
	os.WriteFile(keyFile, []byte("ed25519 "+base64.StdEncoding.EncodeToString(pub)+"\n"), 0o600)
	now := time.Now()
	s, _ := Encode(&Token{ID: "t2", Subject: "ci", Scopes: []string{"deploy:run staging/*"}, IssuedAt: now, ExpiresAt: now.Add(time.Hour)}, priv)
	env := map[string]string{}
	getenv := func(k string) string { return env[k] }

	if tok, err := Guard(getenv, keyFile, "deploy", "run", "prod/api", now); err != nil || tok != nil {
		t.Errorf("no token: want nil,nil; got %v,%v", tok, err)
	}
	env[EnvVar] = s
	if _, err := Guard(getenv, "", "deploy", "run", "staging/api", now); err == nil {
		t.Error("no key file: want error")
	}
	if tok, err := Guard(getenv, keyFile, "deploy", "run", "staging/api", now); err != nil || tok == nil || tok.Subject != "ci" {
		t.Errorf("in scope: got %v,%v", tok, err)
	}
	if _, err := Guard(getenv, keyFile, "deploy", "run", "prod/api", now); err == nil {
		t.Error("out of scope: want error")
	}
	env[EnvKey] = filepath.Join(dir, "missing.pub")
	if _, err := Guard(getenv, keyFile, "deploy", "run", "staging/api", now); err == nil {
		t.Error("env key override missing: want error")
	}
}

func TestGuardPolicy(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	dir := t.TempDir()
	keyFile := filepath.Join(dir, "gate.pub")
	os.WriteFile(keyFile, []byte("ed25519 "+base64.StdEncoding.EncodeToString(pub)+"\n"), 0o600)
	polFile := filepath.Join(dir, "policy.yaml")
	os.WriteFile(polFile, []byte("deny: [\"hetz:destroy *\"]\napprove: [\"ship:deploy prod/*\"]\n"), 0o600)
	now := time.Now()
	s, _ := Encode(&Token{ID: "t3", Subject: "agent", Scopes: []string{"*"}, IssuedAt: now, ExpiresAt: now.Add(time.Hour)}, priv)
	env := map[string]string{EnvVar: s, "INFRA_APPROVALS_DIR": filepath.Join(dir, "approvals")}
	getenv := func(k string) string { return env[k] }

	if tok, err := GuardPolicy(getenv, keyFile, polFile, "ship", "deploy", "staging/api", now); err != nil || tok == nil {
		t.Fatalf("allowed: %v", err)
	}
	var denied *ErrDenied
	if _, err := GuardPolicy(getenv, keyFile, polFile, "hetz", "destroy", "prod", now); !errors.As(err, &denied) {
		t.Fatalf("deny: %v", err)
	}
	var ar *ErrApprovalRequired
	_, err := GuardPolicy(getenv, keyFile, polFile, "ship", "deploy", "prod/api", now)
	if !errors.As(err, &ar) || ar.Subject != "agent" || !strings.Contains(err.Error(), "gate approve "+ar.ID) {
		t.Fatalf("approval: %v", err)
	}
	if _, err := approval.Approve(getenv, ar.ID, "timo", time.Hour, now); err != nil {
		t.Fatal(err)
	}
	if tok, err := GuardPolicy(getenv, keyFile, polFile, "ship", "deploy", "prod/api", now.Add(time.Minute)); err != nil || tok == nil {
		t.Fatalf("after approval: %v", err)
	}
	if _, err := GuardPolicy(getenv, keyFile, polFile, "ship", "deploy", "prod/api", now.Add(2*time.Minute)); !errors.As(err, &ar) {
		t.Fatalf("approval is single use: %v", err)
	}
	// operators (no token) are not subject to the policy
	delete(env, EnvVar)
	if tok, err := GuardPolicy(getenv, keyFile, polFile, "hetz", "destroy", "prod", now); err != nil || tok != nil {
		t.Fatalf("operator: %v %v", tok, err)
	}
}
