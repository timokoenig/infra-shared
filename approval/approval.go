// Package approval is the store of requests that a policy sent for an
// operator's decision: a token holder asks, the request is written under
// $XDG_STATE_HOME/infra/approvals, an operator approves or denies it with
// gate, and the holder's next identical call consumes the approval.
package approval

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// Request is one call waiting for, or holding, a decision.
type Request struct {
	ID        string    `json:"id"`
	Tool      string    `json:"tool"`
	Action    string    `json:"action"`
	Target    string    `json:"target,omitempty"`
	Subject   string    `json:"subject"`  // token subject
	TokenID   string    `json:"token_id"` // the token that asked
	Note      string    `json:"note,omitempty"`
	Requested time.Time `json:"requested"`
	Status    string    `json:"status"` // pending | approved | denied | used
	DecidedBy string    `json:"decided_by,omitempty"`
	Decided   time.Time `json:"decided,omitempty"`
	ExpiresAt time.Time `json:"expires_at,omitempty"` // of an approval
	Used      time.Time `json:"used,omitempty"`
}

// Dir returns the approvals directory.
func Dir(getenv func(string) string) string {
	if d := getenv("INFRA_APPROVALS_DIR"); d != "" {
		return d
	}
	base := getenv("XDG_STATE_HOME")
	if base == "" {
		home := getenv("HOME")
		if home == "" {
			home, _ = os.UserHomeDir()
		}
		base = filepath.Join(home, ".local", "state")
	}
	return filepath.Join(base, "infra", "approvals")
}

// ID derives the request id from what is asked and who asks, so the same
// call by the same subject maps to the same request.
func ID(tool, action, target, subject string) string {
	h := sha256.Sum256([]byte(tool + "\x00" + action + "\x00" + target + "\x00" + subject))
	return hex.EncodeToString(h[:6])
}

func path(getenv func(string) string, id string) string {
	return filepath.Join(Dir(getenv), id+".json")
}

// Get reads one request.
func Get(getenv func(string) string, id string) (*Request, error) {
	b, err := os.ReadFile(path(getenv, id))
	if err != nil {
		return nil, err
	}
	var r Request
	if err := json.Unmarshal(b, &r); err != nil {
		return nil, fmt.Errorf("%s: %w", path(getenv, id), err)
	}
	return &r, nil
}

func save(getenv func(string) string, r *Request) error {
	if err := os.MkdirAll(Dir(getenv), 0o700); err != nil {
		return err
	}
	b, _ := json.MarshalIndent(r, "", "  ")
	return os.WriteFile(path(getenv, r.ID), append(b, '\n'), 0o600)
}

// Ask records a pending request (or returns the existing one). It reports
// whether an approval is available: an approved, unexpired request is
// consumed (marked used) and true is returned.
func Ask(getenv func(string) string, tool, action, target, subject, tokenID, note string, now time.Time) (req *Request, approved bool, err error) {
	id := ID(tool, action, target, subject)
	r, gerr := Get(getenv, id)
	if gerr != nil && !errors.Is(gerr, os.ErrNotExist) {
		return nil, false, gerr
	}
	if r != nil && r.Status == "approved" {
		if now.Before(r.ExpiresAt) {
			r.Status, r.Used = "used", now
			return r, true, save(getenv, r)
		}
		r.Status = "pending" // expired approval: ask again
	}
	if r == nil || r.Status == "used" || r.Status == "denied" && now.Sub(r.Decided) > 24*time.Hour {
		r = &Request{ID: id, Tool: tool, Action: action, Target: target, Subject: subject, Status: "pending"}
	}
	if r.Status == "pending" {
		r.TokenID, r.Note, r.Requested = tokenID, note, now
		return r, false, save(getenv, r)
	}
	return r, false, nil // denied recently: stays denied
}

// Approve marks a pending (or denied) request approved until now+ttl.
func Approve(getenv func(string) string, id, by string, ttl time.Duration, now time.Time) (*Request, error) {
	r, err := Get(getenv, id)
	if err != nil {
		return nil, err
	}
	if r.Status == "used" {
		return nil, fmt.Errorf("request %s was already used", id)
	}
	r.Status, r.DecidedBy, r.Decided, r.ExpiresAt = "approved", by, now, now.Add(ttl)
	return r, save(getenv, r)
}

// Deny marks a request denied.
func Deny(getenv func(string) string, id, by string, now time.Time) (*Request, error) {
	r, err := Get(getenv, id)
	if err != nil {
		return nil, err
	}
	r.Status, r.DecidedBy, r.Decided = "denied", by, now
	return r, save(getenv, r)
}

// List returns every request, newest first.
func List(getenv func(string) string) ([]Request, error) {
	entries, err := os.ReadDir(Dir(getenv))
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, err
	}
	var out []Request
	for _, e := range entries {
		if !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		r, err := Get(getenv, strings.TrimSuffix(e.Name(), ".json"))
		if err == nil {
			out = append(out, *r)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Requested.After(out[j].Requested) })
	return out, nil
}

// Describe renders "ship:deploy prod/api".
func (r *Request) Describe() string {
	s := r.Tool + ":" + r.Action
	if r.Target != "" {
		s += " " + r.Target
	}
	return s
}
