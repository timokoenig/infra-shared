// Package token implements short-lived, scoped tokens: an access tool issues
// them and every other tool honours them. A token is "<base64url payload>.<base64url ed25519
// signature>". Tools call Guard before doing anything; without a token in the
// environment the caller is a human with full access.
//
// Scopes are "<tool>:<action>[ <target glob>]": "deploy:run staging/*",
// "secrets:read staging/*", "monitor:read", "inventory:*", "*". Actions and targets
// are per tool; the target is matched with path.Match against a string the
// tool defines (usually "<env>/<host or service>").
package token

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path"
	"strings"
	"time"
)

// EnvVar holds the token; EnvKey the file with the issuer's public key.
const (
	EnvVar = "INFRA_TOKEN"
	EnvKey = "INFRA_TOKEN_PUBLIC_KEY_FILE"
)

// Token is the signed payload.
type Token struct {
	ID        string    `json:"id"`
	Subject   string    `json:"sub"`           // who: "agent", "ci", a person
	Issuer    string    `json:"iss,omitempty"` // issuing tool / project
	Scopes    []string  `json:"scopes"`
	IssuedAt  time.Time `json:"iat"`
	ExpiresAt time.Time `json:"exp"`
	Note      string    `json:"note,omitempty"`
}

// Encode signs t and returns the wire form.
func Encode(t *Token, priv ed25519.PrivateKey) (string, error) {
	payload, err := json.Marshal(t)
	if err != nil {
		return "", err
	}
	sig := ed25519.Sign(priv, payload)
	enc := base64.RawURLEncoding
	return enc.EncodeToString(payload) + "." + enc.EncodeToString(sig), nil
}

// Decode parses the wire form without verifying it.
func Decode(s string) (t *Token, payload, sig []byte, err error) {
	i := strings.IndexByte(s, '.')
	if i <= 0 || i == len(s)-1 {
		return nil, nil, nil, errors.New("token: not <payload>.<signature>")
	}
	enc := base64.RawURLEncoding
	payload, err = enc.DecodeString(s[:i])
	if err != nil {
		return nil, nil, nil, fmt.Errorf("token payload: %w", err)
	}
	sig, err = enc.DecodeString(s[i+1:])
	if err != nil {
		return nil, nil, nil, fmt.Errorf("token signature: %w", err)
	}
	t = &Token{}
	if err := json.Unmarshal(payload, t); err != nil {
		return nil, nil, nil, fmt.Errorf("token payload: %w", err)
	}
	return t, payload, sig, nil
}

// Verify decodes, checks the signature and expiry.
func Verify(s string, pub ed25519.PublicKey, now time.Time) (*Token, error) {
	t, payload, sig, err := Decode(s)
	if err != nil {
		return nil, err
	}
	if len(pub) != ed25519.PublicKeySize || !ed25519.Verify(pub, payload, sig) {
		return nil, errors.New("token: bad signature")
	}
	if !t.ExpiresAt.IsZero() && now.After(t.ExpiresAt) {
		return nil, fmt.Errorf("token %s expired %s ago", t.ID, now.Sub(t.ExpiresAt).Round(time.Second))
	}
	if !t.IssuedAt.IsZero() && now.Before(t.IssuedAt.Add(-5*time.Minute)) {
		return nil, fmt.Errorf("token %s issued in the future", t.ID)
	}
	return t, nil
}

// Allows reports whether one of the scopes covers tool:action on target.
func (t *Token) Allows(tool, action, target string) bool {
	for _, s := range t.Scopes {
		if scopeAllows(s, tool, action, target) {
			return true
		}
	}
	return false
}

func scopeAllows(scope, tool, action, target string) bool {
	scope = strings.TrimSpace(scope)
	if scope == "*" {
		return true
	}
	ta, tgt, hasTarget := strings.Cut(scope, " ")
	st, sa, ok := strings.Cut(ta, ":")
	if !ok {
		return false
	}
	if st != "*" && st != tool {
		return false
	}
	if sa != "*" && sa != action {
		return false
	}
	if !hasTarget || strings.TrimSpace(tgt) == "" || target == "" {
		return true
	}
	tgt = strings.TrimSpace(tgt)
	if tgt == "*" {
		return true
	}
	m, err := path.Match(tgt, target)
	return err == nil && m
}

// ParseKey reads an ed25519 public key file: raw 32 bytes, or base64 text,
// or "ed25519 <base64>" as the issuing tool writes it.
func ParseKey(b []byte) (ed25519.PublicKey, error) {
	if len(b) == ed25519.PublicKeySize {
		return ed25519.PublicKey(b), nil
	}
	s := strings.TrimSpace(string(b))
	if f := strings.Fields(s); len(f) >= 2 && f[0] == "ed25519" {
		s = f[1]
	}
	for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding} {
		if k, err := enc.DecodeString(s); err == nil && len(k) == ed25519.PublicKeySize {
			return ed25519.PublicKey(k), nil
		}
	}
	return nil, errors.New("not an ed25519 public key")
}

// Guard enforces a token if one is present in the environment. keyFile is
// the issuer's public key (the inventory's tokens.public_key_file); EnvKey
// overrides it. It returns nil with no token (human caller), the verified
// token when in scope, and an error otherwise. The error is meant to be
// shown as-is and exits 1.
func Guard(getenv func(string) string, keyFile, tool, action, target string, now time.Time) (*Token, error) {
	s := getenv(EnvVar)
	if s == "" {
		return nil, nil
	}
	if f := getenv(EnvKey); f != "" {
		keyFile = f
	}
	if keyFile == "" {
		return nil, fmt.Errorf("%s is set but no public key to verify it: set tokens.public_key_file in the inventory or %s", EnvVar, EnvKey)
	}
	b, err := os.ReadFile(expand(getenv, keyFile))
	if err != nil {
		return nil, fmt.Errorf("token public key: %w", err)
	}
	pub, err := ParseKey(b)
	if err != nil {
		return nil, fmt.Errorf("token public key %s: %w", keyFile, err)
	}
	t, err := Verify(s, pub, now)
	if err != nil {
		return nil, err
	}
	if !t.Allows(tool, action, target) {
		want := tool + ":" + action
		if target != "" {
			want += " " + target
		}
		return nil, fmt.Errorf("token %s (%s) does not allow %s; scopes: %s", t.ID, t.Subject, want, strings.Join(t.Scopes, ", "))
	}
	return t, nil
}

func expand(getenv func(string) string, p string) string {
	if strings.HasPrefix(p, "~/") {
		home := getenv("HOME")
		if home == "" {
			home, _ = os.UserHomeDir()
		}
		return home + p[1:]
	}
	return p
}
