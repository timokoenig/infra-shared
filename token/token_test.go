package token

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"os"
	"path/filepath"
	"testing"
	"time"
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
