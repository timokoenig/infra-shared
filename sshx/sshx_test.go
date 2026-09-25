package sshx

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/timokoenig/infra-shared/inventory"
)

func TestArgv(t *testing.T) {
	direct := []inventory.Hop{{Host: "web-1", Address: "1.2.3.4", User: "root", Port: 22}}
	argv, err := Argv(direct, Options{}, []string{"uptime"})
	if err != nil {
		t.Fatal(err)
	}
	want := "ssh -o ConnectTimeout=10 -o BatchMode=yes -p 22 -l root 1.2.3.4 -- uptime"
	if got := strings.Join(argv, " "); got != want {
		t.Errorf("direct:\n got %s\nwant %s", got, want)
	}
	jump := []inventory.Hop{{Host: "hub-1", Address: "5.6.7.8", User: "root", Port: 22}, {Host: "bastion", Address: "2001:db8::1", User: "ops", Port: 2222}, {Host: "db-1", Address: "10.0.1.3", User: "deploy", Port: 22}}
	argv, err = Argv(jump, Options{Interactive: true, IdentityFile: "~/.ssh/id"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	want = "ssh -o ConnectTimeout=10 -i ~/.ssh/id -J root@5.6.7.8,ops@[2001:db8::1]:2222 -p 22 -l deploy 10.0.1.3"
	if got := strings.Join(argv, " "); got != want {
		t.Errorf("jump:\n got %s\nwant %s", got, want)
	}
	if _, err := Argv([]inventory.Hop{{Host: "x", User: "root", Port: 22}}, Options{}, nil); err == nil {
		t.Error("missing address: want error")
	}
}

func TestRunnerAndLock(t *testing.T) {
	route := []inventory.Hop{{Host: "web-1", Address: "1.2.3.4", User: "root", Port: 22}}
	var lastStdin string
	r := &Runner{Exec: func(ctx context.Context, argv []string, stdin []byte) ([]byte, []byte, int, error) {
		lastStdin = string(stdin)
		switch {
		case strings.Contains(lastStdin, "infra.lock") && strings.Contains(lastStdin, "o='agent'"):
			return []byte("held by timo for 12s\n"), nil, 3, nil
		case strings.Contains(lastStdin, "infra.lock"):
			return []byte("locked\n"), nil, 0, nil
		case argv[len(argv)-1] == "true":
			return nil, []byte("Permission denied (publickey).\n"), 255, nil
		}
		return []byte("ok"), nil, 0, nil
	}}
	res, err := r.Run(context.Background(), route, "echo hi")
	if err != nil || res.Stdout != "ok" || lastStdin != "echo hi" {
		t.Errorf("run: %+v %v stdin=%q", res, err, lastStdin)
	}
	if err := r.Ping(context.Background(), route); err == nil || !strings.Contains(err.Error(), "Permission denied") {
		t.Errorf("ping: want ssh error, got %v", err)
	}
	unlock, err := r.Lock(context.Background(), route, "timo laptop")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(lastStdin, "o='timo_laptop'") {
		t.Errorf("owner not quoted: %s", lastStdin)
	}
	if err := unlock(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Lock(context.Background(), route, "agent"); !errors.Is(err, ErrLocked) || !strings.Contains(err.Error(), "held by timo") {
		t.Errorf("locked: got %v", err)
	}
}
