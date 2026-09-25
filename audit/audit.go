// Package audit appends one JSON line per mutating command to a local log,
// so "what changed, when, by whom" is one file:
// $XDG_STATE_HOME/infra/audit.jsonl, default ~/.local/state/infra/audit.jsonl.
// Every tool writes the same record; an inventory tool reads them back.
package audit

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Record is one audited command.
type Record struct {
	Time     time.Time     `json:"time"`
	Tool     string        `json:"tool"`
	Version  string        `json:"version,omitempty"`
	Command  string        `json:"command"`
	Args     []string      `json:"args,omitempty"`
	Env      string        `json:"env,omitempty"`
	Hosts    []string      `json:"hosts,omitempty"`
	Identity string        `json:"identity"` // local user, or the token subject
	TokenID  string        `json:"token_id,omitempty"`
	ExitCode int           `json:"exit_code"`
	Duration time.Duration `json:"duration_ms"`
	Error    string        `json:"error,omitempty"`
	Note     string        `json:"note,omitempty"` // free text a tool adds (e.g. the plan summary)
}

// MarshalJSON renders Duration in milliseconds.
func (r Record) MarshalJSON() ([]byte, error) {
	type raw Record
	x := struct {
		raw
		Duration int64 `json:"duration_ms"`
	}{raw(r), r.Duration.Milliseconds()}
	return json.Marshal(x)
}

// UnmarshalJSON reads duration_ms back.
func (r *Record) UnmarshalJSON(b []byte) error {
	type raw Record
	var x struct {
		raw
		Duration int64 `json:"duration_ms"`
	}
	if err := json.Unmarshal(b, &x); err != nil {
		return err
	}
	*r = Record(x.raw)
	r.Duration = time.Duration(x.Duration) * time.Millisecond
	return nil
}

// Path returns the log file path.
func Path(getenv func(string) string) string {
	if p := getenv("INFRA_AUDIT_LOG"); p != "" {
		return p
	}
	dir := getenv("XDG_STATE_HOME")
	if dir == "" {
		home := getenv("HOME")
		if home == "" {
			home, _ = os.UserHomeDir()
		}
		dir = filepath.Join(home, ".local", "state")
	}
	return filepath.Join(dir, "infra", "audit.jsonl")
}

// Identity is who runs the command: INFRA_IDENTITY, the token subject set by
// the token package, or the local user.
func Identity(getenv func(string) string) string {
	for _, k := range []string{"INFRA_IDENTITY", "USER", "LOGNAME"} {
		if v := getenv(k); v != "" {
			return v
		}
	}
	return "unknown"
}

// Append writes one record. Failure to write never fails the command that
// is audited; the caller warns.
func Append(getenv func(string) string, r Record) error {
	if getenv("INFRA_AUDIT_LOG") == "off" {
		return nil
	}
	path := Path(getenv)
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()
	b, err := json.Marshal(r)
	if err != nil {
		return err
	}
	_, err = f.Write(append(b, '\n'))
	return err
}

// Read returns records newer than since (zero = all), newest last. A
// corrupt line is skipped with an error that names it once.
func Read(getenv func(string) string, since time.Time) ([]Record, error) {
	f, err := os.Open(Path(getenv))
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, err
	}
	defer f.Close()
	var out []Record
	var bad int
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		var r Record
		if err := json.Unmarshal([]byte(line), &r); err != nil {
			bad++
			continue
		}
		if !since.IsZero() && r.Time.Before(since) {
			continue
		}
		out = append(out, r)
	}
	if err := sc.Err(); err != nil {
		return out, err
	}
	if bad > 0 {
		return out, fmt.Errorf("%d unreadable lines skipped in %s", bad, Path(getenv))
	}
	return out, nil
}
