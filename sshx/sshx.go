// Package sshx runs commands on hosts through the system ssh binary,
// following the route the inventory resolved (jump hosts as -J). It also
// provides a per-host lock so two tools never change one host at once.
package sshx

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"github.com/timokoenig/infra-shared/inventory"
)

// Options tune the ssh invocation.
type Options struct {
	// ConnectTimeout in seconds; default 10.
	ConnectTimeout int
	// IdentityFile passes -i. Optional.
	IdentityFile string
	// Extra ssh options (-o k=v). Optional.
	Extra []string
	// Interactive keeps a tty (no BatchMode); for an interactive ssh command.
	Interactive bool
}

// Argv builds the ssh command line for a route. cmd is run on the host;
// empty means an interactive shell.
func Argv(route []inventory.Hop, o Options, cmd []string) ([]string, error) {
	if len(route) == 0 {
		return nil, errors.New("empty route")
	}
	for _, h := range route {
		if h.Address == "" {
			return nil, fmt.Errorf("host %s has no address (run without --offline, or set address in the inventory)", h.Host)
		}
	}
	to := o.ConnectTimeout
	if to == 0 {
		to = 10
	}
	argv := []string{"ssh", "-o", "ConnectTimeout=" + strconv.Itoa(to)}
	if !o.Interactive {
		// BatchMode never prompts, so a host seen for the first time (a fresh server) must be
		// accepted on first use; a changed key is still refused, as it should be.
		argv = append(argv, "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=accept-new")
	}
	if o.IdentityFile != "" {
		argv = append(argv, "-i", o.IdentityFile)
	}
	for _, e := range o.Extra {
		argv = append(argv, "-o", e)
	}
	if len(route) > 1 {
		jumps := make([]string, 0, len(route)-1)
		for _, h := range route[:len(route)-1] {
			jumps = append(jumps, hopSpec(h))
		}
		argv = append(argv, "-J", strings.Join(jumps, ","))
	}
	last := route[len(route)-1]
	argv = append(argv, "-p", strconv.Itoa(last.Port), "-l", last.User, last.Address)
	if len(cmd) > 0 {
		argv = append(argv, "--")
		argv = append(argv, cmd...)
	}
	return argv, nil
}

func hopSpec(h inventory.Hop) string {
	s := h.Address
	if strings.Contains(s, ":") { // IPv6
		s = "[" + s + "]"
	}
	if h.User != "" {
		s = h.User + "@" + s
	}
	if h.Port != 0 && h.Port != 22 {
		s += ":" + strconv.Itoa(h.Port)
	}
	return s
}

// Result of a remote command.
type Result struct {
	Stdout   string
	Stderr   string
	ExitCode int
	Duration time.Duration
}

// Runner executes remote commands.
type Runner struct {
	Options Options
	// Exec runs argv with stdin and returns stdout, stderr and the exit code.
	// Nil uses os/exec. Tests inject it.
	Exec func(ctx context.Context, argv []string, stdin []byte) (stdout, stderr []byte, code int, err error)
	// Timeout per command; default 5m.
	Timeout time.Duration
}

// Run executes a shell script on the host (through `sh -s` with the
// script on stdin, so quoting never matters).
func (r *Runner) Run(ctx context.Context, route []inventory.Hop, script string) (Result, error) {
	argv, err := Argv(route, r.Options, []string{"sh", "-s"})
	if err != nil {
		return Result{}, err
	}
	return r.exec(ctx, argv, []byte(script))
}

// Command runs a single command with arguments on the host.
func (r *Runner) Command(ctx context.Context, route []inventory.Hop, cmd ...string) (Result, error) {
	argv, err := Argv(route, r.Options, cmd)
	if err != nil {
		return Result{}, err
	}
	return r.exec(ctx, argv, nil)
}

func (r *Runner) exec(ctx context.Context, argv []string, stdin []byte) (Result, error) {
	to := r.Timeout
	if to == 0 {
		to = 5 * time.Minute
	}
	ctx, cancel := context.WithTimeout(ctx, to)
	defer cancel()
	ex := r.Exec
	if ex == nil {
		ex = execDefault
	}
	start := time.Now()
	out, errb, code, err := ex(ctx, argv, stdin)
	res := Result{Stdout: string(out), Stderr: string(errb), ExitCode: code, Duration: time.Since(start)}
	if err != nil {
		return res, err
	}
	if code == 255 {
		msg := strings.TrimSpace(res.Stderr)
		if msg == "" {
			msg = "ssh failed"
		}
		return res, fmt.Errorf("ssh %s: %s", target(argv), lastLine(msg))
	}
	return res, nil
}

// target is the host argument of an ssh argv (the word before "--", else the last).
func target(argv []string) string {
	for i, a := range argv {
		if a == "--" && i > 0 {
			return argv[i-1]
		}
	}
	return argv[len(argv)-1]
}

func lastLine(s string) string {
	lines := strings.Split(strings.TrimSpace(s), "\n")
	return strings.TrimSpace(lines[len(lines)-1])
}

func execDefault(ctx context.Context, argv []string, stdin []byte) ([]byte, []byte, int, error) {
	cmd := exec.CommandContext(ctx, argv[0], argv[1:]...)
	var out, errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errb
	if stdin != nil {
		cmd.Stdin = bytes.NewReader(stdin)
	}
	err := cmd.Run()
	code := 0
	if err != nil {
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			code, err = ee.ExitCode(), nil
		}
	}
	if ctx.Err() != nil && err == nil {
		err = ctx.Err()
	}
	return out.Bytes(), errb.Bytes(), code, err
}

// Ping checks that the host answers ssh (`true`).
func (r *Runner) Ping(ctx context.Context, route []inventory.Hop) error {
	res, err := r.Command(ctx, route, "true")
	if err != nil {
		return err
	}
	if res.ExitCode != 0 {
		return fmt.Errorf("exit %d: %s", res.ExitCode, lastLine(res.Stderr))
	}
	return nil
}

// Put writes content to path on the host with the given mode (e.g. "0644"),
// atomically (temp file + install), creating parent directories. sudo is
// used when the user is not root. The script travels as one quoted
// argument, so the remote shell runs it whole and its exit status is real.
func (r *Runner) Put(ctx context.Context, route []inventory.Hop, path string, content []byte, mode string) error {
	if mode == "" {
		mode = "0644"
	}
	sudo := ""
	if len(route) > 0 && route[len(route)-1].User != "root" {
		sudo = "sudo "
	}
	dir := path[:strings.LastIndex(path, "/")+1]
	if dir == "" {
		dir = "."
	}
	script := fmt.Sprintf("set -e\nt=$(mktemp)\ncat > \"$t\"\n%smkdir -p %s\n%sinstall -m %s \"$t\" %s\nrm -f \"$t\"\n", sudo, shellQuote(dir), sudo, shellQuote(mode), shellQuote(path))
	argv, err := Argv(route, r.Options, []string{"sh", "-c", shellQuote(script)})
	if err != nil {
		return err
	}
	res, err := r.exec(ctx, argv, content)
	if err != nil {
		return err
	}
	if res.ExitCode != 0 {
		return fmt.Errorf("put %s: exit %d: %s", path, res.ExitCode, lastLine(res.Stderr))
	}
	return nil
}

// LockStale is how old a lock may be before another owner takes it over.
const LockStale = time.Hour

// ErrLocked is returned when another owner holds the host.
var ErrLocked = errors.New("host is locked")

// Lock takes the per-host lock (/run/lock/infra.lock, or /tmp when not
// writable). It returns an unlock function. A lock older than LockStale is
// taken over. When another owner holds it the error wraps ErrLocked and
// names the owner; tools exit 3 on it.
func (r *Runner) Lock(ctx context.Context, route []inventory.Hop, owner string) (func(context.Context) error, error) {
	owner = strings.Map(func(c rune) rune {
		if c == ' ' || c == '\n' {
			return '_'
		}
		return c
	}, owner)
	script := fmt.Sprintf(`d=/run/lock; [ -w "$d" ] || d=/tmp; f="$d/infra.lock"; o=%s; now=$(date +%%s)
if ( set -C; echo "$o $now" > "$f" ) 2>/dev/null; then echo locked; exit 0; fi
read ho ht < "$f" 2>/dev/null || ho=unknown; ht=${ht:-0}
if [ "$ho" = "$o" ]; then echo "$o $now" > "$f"; echo relocked; exit 0; fi
if [ $((now - ht)) -gt %d ]; then echo "$o $now" > "$f"; echo "took over stale lock of $ho"; exit 0; fi
echo "held by $ho for $((now - ht))s"; exit 3
`, shellQuote(owner), int(LockStale.Seconds()))
	res, err := r.Run(ctx, route, script)
	if err != nil {
		return nil, err
	}
	if res.ExitCode == 3 {
		return nil, fmt.Errorf("%w: %s", ErrLocked, lastLine(res.Stdout))
	}
	if res.ExitCode != 0 {
		return nil, fmt.Errorf("lock: exit %d: %s", res.ExitCode, lastLine(res.Stderr))
	}
	unlock := func(ctx context.Context) error {
		s := fmt.Sprintf(`d=/run/lock; [ -w "$d" ] || d=/tmp; f="$d/infra.lock"; o=%s
read ho ht < "$f" 2>/dev/null || exit 0; [ "$ho" = "$o" ] && rm -f "$f"; exit 0
`, shellQuote(owner))
		_, err := r.Run(ctx, route, s)
		return err
	}
	return unlock, nil
}

func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}
