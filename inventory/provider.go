package inventory

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os/exec"
	"strings"
	"time"
)

// ProviderCLI resolves servers by running the provider's CLI:
//
//	<command> status --json --env <env> [--file <file>]
//
// and reading {"resources": [{"type": "server", "name", "id", "state",
// "spec", "location", "ipv4", "ipv6"}, ...]} from its stdout. Only
// resources of type "server" are used; "spec" is the server type and
// "ipv6" may be the /64 prefix. The CLI and its JSON output are the whole
// contract; the provider tool is a separate program.
type ProviderCLI struct {
	// DefaultCommand is the executable when the inventory's provider has no
	// command of its own.
	DefaultCommand string
	// Timeout per call; default 60s.
	Timeout time.Duration
	// Run executes argv and returns stdout; nil uses os/exec. Tests inject it.
	Run func(ctx context.Context, argv []string) ([]byte, error)
}

type providerStatus struct {
	Resources []struct {
		Type     string `json:"type"`
		Name     string `json:"name"`
		ID       int64  `json:"id"`
		State    string `json:"state"`
		Spec     string `json:"spec"`
		Location string `json:"location"`
		IPv4     string `json:"ipv4"`
		IPv6     string `json:"ipv6"`
	} `json:"resources"`
}

// Servers implements Lookup.
func (h *ProviderCLI) Servers(ctx context.Context, p Provider, env string) ([]Server, error) {
	bin := p.Command
	if bin == "" {
		bin = h.DefaultCommand
	}
	if bin == "" {
		return nil, errors.New("no provider command configured (provider.command in the inventory)")
	}
	argv := []string{bin, "status", "--json", "--env", env}
	if p.File != "" {
		argv = append(argv, "--file", p.File)
	}
	to := h.Timeout
	if to == 0 {
		to = 60 * time.Second
	}
	ctx, cancel := context.WithTimeout(ctx, to)
	defer cancel()
	run := h.Run
	if run == nil {
		run = runExec
	}
	out, err := run(ctx, argv)
	if err != nil {
		return nil, err
	}
	var st providerStatus
	if err := json.Unmarshal(out, &st); err != nil {
		return nil, fmt.Errorf("%s status --json: %w", bin, err)
	}
	var servers []Server
	for _, r := range st.Resources {
		if r.Type != "server" {
			continue
		}
		ip6 := r.IPv6
		if ip6 != "" {
			// Providers report the /64; the server itself answers on ::1.
			ip6 = strings.TrimSuffix(strings.TrimSuffix(ip6, "/64"), "::") + "::1"
		}
		servers = append(servers, Server{Name: r.Name, ID: r.ID, State: r.State, Type: r.Spec, Location: r.Location, IPv4: r.IPv4, IPv6: ip6})
	}
	return servers, nil
}

func runExec(ctx context.Context, argv []string) ([]byte, error) {
	if _, err := exec.LookPath(argv[0]); err != nil {
		return nil, fmt.Errorf("%s not found on PATH (install it or pass --offline)", argv[0])
	}
	cmd := exec.CommandContext(ctx, argv[0], argv[1:]...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if err := cmd.Run(); err != nil {
		msg := strings.TrimSpace(stderr.String())
		var je struct {
			Error string `json:"error"`
		}
		if json.Unmarshal([]byte(msg), &je) == nil && je.Error != "" {
			msg = je.Error
		}
		if msg == "" {
			msg = err.Error()
		}
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			return nil, fmt.Errorf("%s exit %d: %s", strings.Join(argv[:2], " "), ee.ExitCode(), msg)
		}
		return nil, fmt.Errorf("%s: %s", argv[0], msg)
	}
	return stdout.Bytes(), nil
}
