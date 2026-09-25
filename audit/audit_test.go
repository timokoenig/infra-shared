package audit

import (
	"path/filepath"
	"testing"
	"time"
)

func TestAppendRead(t *testing.T) {
	dir := t.TempDir()
	env := map[string]string{"XDG_STATE_HOME": dir, "USER": "timo"}
	getenv := func(k string) string { return env[k] }
	if p := Path(getenv); p != filepath.Join(dir, "infra", "audit.jsonl") {
		t.Fatalf("path %s", p)
	}
	now := time.Date(2026, 9, 25, 12, 0, 0, 0, time.UTC)
	for i, tool := range []string{"config", "deploy", "inventory"} {
		r := Record{Time: now.Add(time.Duration(i) * time.Hour), Tool: tool, Command: "apply", Args: []string{"web-1"}, Env: "prod",
			Hosts: []string{"web-1"}, Identity: Identity(getenv), ExitCode: i, Duration: 1500 * time.Millisecond}
		if err := Append(getenv, r); err != nil {
			t.Fatal(err)
		}
	}
	all, err := Read(getenv, time.Time{})
	if err != nil {
		t.Fatal(err)
	}
	if len(all) != 3 || all[0].Tool != "config" || all[0].Identity != "timo" || all[0].Duration != 1500*time.Millisecond || all[2].ExitCode != 2 {
		t.Fatalf("records: %+v", all)
	}
	recent, err := Read(getenv, now.Add(90*time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if len(recent) != 1 || recent[0].Tool != "inventory" {
		t.Fatalf("since filter: %+v", recent)
	}
	if got, _ := Read(func(string) string { return filepath.Join(t.TempDir(), "none") }, time.Time{}); got != nil {
		t.Errorf("missing file: want nil")
	}
}
