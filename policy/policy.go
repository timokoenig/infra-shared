// Package policy reads policy.yaml: rules that apply to every token holder
// (agents, CI) on top of the token's own scopes. Operators without a token
// are not subject to it.
//
//	deny:                        # never, whatever the token says
//	  - "hetz:destroy *"
//	  - "*:* prod/*"             # any tool, any action on prod
//	approve:                     # allowed only after an operator approved this exact request (gate approve)
//	  - "ship:deploy prod/*"
//	  - "rig:apply *"
//	approval_ttl: 1h             # how long an approval stays valid; default 1h
//
// A pattern is "<tool>:<action> [target-glob]" like a token scope; "*"
// matches any tool or action, a missing target matches every target.
package policy

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// Policy is policy.yaml.
type Policy struct {
	Deny        []string `yaml:"deny,omitempty"`
	Approve     []string `yaml:"approve,omitempty"`
	ApprovalTTL string   `yaml:"approval_ttl,omitempty"`

	Path string `yaml:"-"`
}

// Decision is what the policy says about one call.
type Decision int

// Decisions.
const (
	Allow Decision = iota
	NeedsApproval
	Deny
)

func (d Decision) String() string {
	switch d {
	case NeedsApproval:
		return "needs-approval"
	case Deny:
		return "deny"
	}
	return "allow"
}

// Load reads policy.yaml. A missing file (or empty path) is an empty policy.
func Load(path string) (*Policy, error) {
	if path == "" {
		return &Policy{}, nil
	}
	b, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return &Policy{Path: path}, nil
		}
		return nil, err
	}
	dec := yaml.NewDecoder(bytes.NewReader(b))
	dec.KnownFields(true)
	p := &Policy{Path: path}
	if err := dec.Decode(p); err != nil && err.Error() != "EOF" {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	if err := p.Validate(); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return p, nil
}

// Validate checks the patterns.
func (p *Policy) Validate() error {
	for _, list := range [][]string{p.Deny, p.Approve} {
		for _, pat := range list {
			if !patternOK(pat) {
				return fmt.Errorf("%q is not \"<tool>:<action> [target]\"", pat)
			}
		}
	}
	if p.ApprovalTTL != "" {
		if _, err := time.ParseDuration(p.ApprovalTTL); err != nil {
			return fmt.Errorf("approval_ttl: %w", err)
		}
	}
	return nil
}

// TTL of an approval.
func (p *Policy) TTL() time.Duration {
	if p.ApprovalTTL == "" {
		return time.Hour
	}
	d, _ := time.ParseDuration(p.ApprovalTTL)
	return d
}

func patternOK(pat string) bool {
	ta, _, _ := strings.Cut(strings.TrimSpace(pat), " ")
	if ta == "*" {
		return true
	}
	tool, action, ok := strings.Cut(ta, ":")
	return ok && tool != "" && action != ""
}

// Decide returns Deny, NeedsApproval or Allow for a call.
func (p *Policy) Decide(tool, action, target string) Decision {
	for _, pat := range p.Deny {
		if Matches(pat, tool, action, target) {
			return Deny
		}
	}
	for _, pat := range p.Approve {
		if Matches(pat, tool, action, target) {
			return NeedsApproval
		}
	}
	return Allow
}

// Matches reports whether a pattern covers tool:action on target.
func Matches(pat, tool, action, target string) bool {
	pat = strings.TrimSpace(pat)
	if pat == "*" {
		return true
	}
	ta, tgt, hasTarget := strings.Cut(pat, " ")
	pt, pa, _ := strings.Cut(ta, ":")
	if pt != "*" && pt != tool {
		return false
	}
	if pa != "*" && pa != action {
		return false
	}
	tgt = strings.TrimSpace(tgt)
	if !hasTarget || tgt == "" || tgt == "*" {
		return true
	}
	if target == "" {
		return false
	}
	m, err := path.Match(tgt, target)
	return err == nil && m
}
