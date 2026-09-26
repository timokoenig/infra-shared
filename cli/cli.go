// Package cli is the command skeleton shared by every infra tool: global
// flags, a command table, positional-anywhere flag parsing, exit codes,
// error rendering (plain or JSON) and the audit hook for mutating commands.
//
// A tool builds an App, adds Commands and calls Main. The conventions: never
// prompt, --json on every command,
// exit 0 ok / 1 failed / 2 usage / 3 problems, errors on stderr as
// "error: ..." or {"error":...,"exit_code":n}.
package cli

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"github.com/timokoenig/infra-shared/inventory"
	"io"
	"os"
	"os/signal"
	"sort"
	"strings"
	"syscall"
	"time"

	"github.com/timokoenig/infra-shared/audit"
)

// Exit codes.
const (
	ExitOK       = 0
	ExitError    = 1 // request, ssh or apply error
	ExitUsage    = 2 // bad flags, config file or parameters
	ExitProblems = 3 // plan has changes, validate found problems, a check failed, apply refused
)

// Error carries an exit code with an error. A nil Err with a code means
// "exit silently with this code" (used for --help).
type Error struct {
	Code int
	Err  error
}

func (e *Error) Error() string {
	if e.Err == nil {
		return ""
	}
	return e.Err.Error()
}

func (e *Error) Unwrap() error { return e.Err }

// Usage returns an exit-2 error.
func Usage(msg string) error { return &Error{Code: ExitUsage, Err: errors.New(msg)} }

// Usagef returns an exit-2 error.
func Usagef(format string, args ...any) error {
	return &Error{Code: ExitUsage, Err: fmt.Errorf(format, args...)}
}

// Problems returns an exit-3 error.
func Problems(msg string) error { return &Error{Code: ExitProblems, Err: errors.New(msg)} }

// Problemsf returns an exit-3 error.
func Problemsf(format string, args ...any) error {
	return &Error{Code: ExitProblems, Err: fmt.Errorf(format, args...)}
}

// Failed returns an exit-1 error.
func Failed(msg string) error { return &Error{Code: ExitError, Err: errors.New(msg)} }

// Failedf returns an exit-1 error.
func Failedf(format string, args ...any) error {
	return &Error{Code: ExitError, Err: fmt.Errorf(format, args...)}
}

// Silent exits with code and no message.
func Silent(code int) error { return &Error{Code: code} }

// Globals are the flags every tool accepts before or after the command.
type Globals struct {
	JSON      bool
	UTC       bool
	Offline   bool
	Inventory string // path of infra.yaml
	Env       string // environment name
	Confirm   string // --confirm ENV: the protected environment this command may change
}

// Command is one subcommand.
type Command struct {
	Name    string
	Aliases []string
	Usage   string // e.g. "hosts [--role R]"
	Summary string
	// Mutating commands are appended to the audit log with their result, and
	// refused on a protected environment without --confirm <env>.
	Mutating bool
	// Local marks a mutating command that touches only this machine (init,
	// keys, approvals): no environment guard.
	Local bool
	Run   func(c *Ctx, args []string) error
}

// App describes a tool.
type App struct {
	Name     string
	Version  string
	Summary  string // one line after "name version -"
	Footer   string // printed after the command list in usage
	Commands []Command
	// Flags adds tool-specific global flags. Optional.
	Flags func(fs *flag.FlagSet)
	// Loop is the "typical loop" line in usage. Optional.
	Loop string

	Stdin  io.Reader
	Stdout io.Writer
	Stderr io.Writer
	Getenv func(string) string
	Now    func() time.Time
	// Exec runs an interactive program (ssh). Optional; defaults to os/exec with the process's stdio.
	Exec func(ctx context.Context, argv []string) error
}

// Ctx is what a command receives.
type Ctx struct {
	*App
	Globals
	cmd string
}

// Main runs the tool and returns the exit code.
func (a *App) Main(args []string) int {
	a.defaults()
	c := &Ctx{App: a}
	c.Inventory = a.Getenv("INFRA_FILE")
	c.Env = a.Getenv("INFRA_ENV")
	c.Confirm = a.Getenv("INFRA_CONFIRM")
	gfs := flag.NewFlagSet(a.Name, flag.ContinueOnError)
	gfs.SetOutput(io.Discard)
	c.globalFlags(gfs)
	if err := gfs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			a.PrintUsage(a.Stdout)
			return ExitOK
		}
		fmt.Fprintln(a.Stderr, "error:", err)
		return ExitUsage
	}
	rest := gfs.Args()
	if len(rest) == 0 {
		a.PrintUsage(a.Stderr)
		return ExitUsage
	}
	name, rest := rest[0], rest[1:]
	if name == "help" || name == "-h" || name == "--help" {
		a.PrintUsage(a.Stdout)
		return ExitOK
	}
	cmd := a.lookup(name)
	if cmd == nil {
		fmt.Fprintf(a.Stderr, "error: unknown command %q (see %s help)\n", name, a.Name)
		return ExitUsage
	}
	c.cmd = cmd.Name
	start := a.Now()
	var err error
	if cmd.Mutating && !cmd.Local {
		err = c.guardProtectedEnv()
	}
	if err == nil {
		err = cmd.Run(c, rest)
	}
	code := c.Finish(err)
	if cmd.Mutating {
		rec := audit.Record{Time: start, Tool: a.Name, Version: a.Version, Command: cmd.Name, Args: rest, Env: c.Env,
			ExitCode: code, Duration: a.Now().Sub(start), Identity: audit.Identity(a.Getenv)}
		if err != nil && code != ExitOK {
			rec.Error = err.Error()
		}
		if aerr := audit.Append(a.Getenv, rec); aerr != nil {
			c.Warnf("audit log: %v", aerr)
		}
	}
	return code
}

func (a *App) defaults() {
	if a.Stdin == nil {
		a.Stdin = os.Stdin
	}
	if a.Stdout == nil {
		a.Stdout = os.Stdout
	}
	if a.Stderr == nil {
		a.Stderr = os.Stderr
	}
	if a.Getenv == nil {
		a.Getenv = os.Getenv
	}
	if a.Now == nil {
		a.Now = time.Now
	}
	if a.Exec == nil {
		a.Exec = execInteractive
	}
	if a.Version == "" {
		a.Version = "dev"
	}
	if a.lookup("version") == nil {
		a.Commands = append(a.Commands, Command{Name: "version", Usage: "version", Summary: "Print the CLI version",
			Run: func(c *Ctx, _ []string) error { fmt.Fprintln(c.Stdout, c.Version); return nil }})
	}
}

func (a *App) lookup(name string) *Command {
	for i := range a.Commands {
		if a.Commands[i].Name == name {
			return &a.Commands[i]
		}
		for _, al := range a.Commands[i].Aliases {
			if al == name {
				return &a.Commands[i]
			}
		}
	}
	return nil
}

// Finish renders err and returns the exit code.
func (c *Ctx) Finish(err error) int {
	if err == nil {
		return ExitOK
	}
	var e *Error
	if errors.As(err, &e) {
		if e.Err != nil {
			c.Errorf(e.Code, e.Err)
		}
		return e.Code
	}
	if errors.Is(err, flag.ErrHelp) {
		return ExitOK
	}
	if errors.Is(err, context.Canceled) {
		c.Errorf(ExitError, errors.New("interrupted"))
		return ExitError
	}
	c.Errorf(ExitError, err)
	return ExitError
}

// Errorf prints an error the way the output mode wants it.
func (c *Ctx) Errorf(code int, err error) {
	if c.JSON {
		fmt.Fprintf(c.Stderr, "{\"error\":%q,\"exit_code\":%d}\n", err.Error(), code)
		return
	}
	fmt.Fprintln(c.Stderr, "error:", err.Error())
}

// Warnf prints a warning on stderr.
func (c *Ctx) Warnf(format string, args ...any) {
	fmt.Fprintf(c.Stderr, "warning: "+format+"\n", args...)
}

func (c *Ctx) globalFlags(fs *flag.FlagSet) {
	fs.StringVar(&c.Inventory, "inventory", c.Inventory, "infra.yaml to use (default ./infra.yaml, env INFRA_FILE)")
	fs.StringVar(&c.Inventory, "i", c.Inventory, "shorthand for --inventory")
	fs.StringVar(&c.Env, "env", c.Env, "environment to work on (env INFRA_ENV, else default_env)")
	fs.StringVar(&c.Env, "e", c.Env, "shorthand for --env")
	fs.BoolVar(&c.JSON, "json", c.JSON, "machine-readable output on stdout (for scripts and agents)")
	fs.BoolVar(&c.JSON, "j", c.JSON, "shorthand for --json")
	fs.BoolVar(&c.UTC, "utc", c.UTC, "print times as UTC RFC 3339 instead of relative")
	fs.StringVar(&c.Confirm, "confirm", c.Confirm, "name of a protected environment this command may change (env INFRA_CONFIRM)")
	fs.BoolVar(&c.Offline, "offline", c.Offline, "never call the provider or a host; resolve from the inventory only")
	if c.App.Flags != nil {
		c.App.Flags(fs)
	}
}

// Flags creates a subcommand flag set that also accepts the global flags.
func (c *Ctx) Flags(cmd string) *flag.FlagSet {
	fs := flag.NewFlagSet(cmd, flag.ContinueOnError)
	fs.SetOutput(c.Stderr)
	fs.Usage = func() {
		if cc := c.lookup(cmd); cc != nil {
			fmt.Fprintf(c.Stderr, "usage: %s %s\n\n%s\n\nflags:\n", c.Name, cc.Usage, cc.Summary)
		}
		fs.PrintDefaults()
	}
	c.globalFlags(fs)
	return fs
}

// Parse parses subcommand flags. Positional arguments may appear before,
// between or after flags. Everything after "--" is returned as extra.
func (c *Ctx) Parse(fs *flag.FlagSet, args []string) (positional, extra []string, err error) {
	rest := args
	for i, arg := range rest {
		if arg == "--" {
			extra = rest[i+1:]
			rest = rest[:i]
			break
		}
	}
	for {
		if err := fs.Parse(rest); err != nil {
			if errors.Is(err, flag.ErrHelp) {
				return nil, nil, Silent(ExitOK)
			}
			return nil, nil, Usage(err.Error())
		}
		rest = fs.Args()
		if len(rest) == 0 {
			break
		}
		positional = append(positional, rest[0])
		rest = rest[1:]
	}
	return positional, extra, nil
}

// Context returns a context cancelled by SIGINT/SIGTERM.
func (c *Ctx) Context() (context.Context, context.CancelFunc) {
	return signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
}

// PrintUsage prints the command list and global flags.
func (a *App) PrintUsage(w io.Writer) {
	fmt.Fprintf(w, "%s %s - %s\n\nusage: %s [global flags] <command> [flags]\n\ncommands:\n", a.Name, a.Version, a.Summary, a.Name)
	tw := TabWriter(w)
	names := make([]string, 0, len(a.Commands))
	byName := map[string]Command{}
	for _, c := range a.Commands {
		names = append(names, c.Name)
		byName[c.Name] = c
	}
	sort.Strings(names)
	for _, n := range names {
		c := byName[n]
		alias := ""
		if len(c.Aliases) > 0 {
			alias = " (" + strings.Join(c.Aliases, ", ") + ")"
		}
		fmt.Fprintf(tw, "  %s%s\t%s\n", c.Name, alias, c.Summary)
	}
	tw.Flush()
	fmt.Fprint(w, `
global flags (before or after the command):
  -i, --inventory PATH  infra.yaml                     default ./infra.yaml, env INFRA_FILE
  -e, --env NAME        environment                    env INFRA_ENV, else default_env in the file
  -j, --json            machine-readable stdout (one JSON document per command)
  --utc                 absolute UTC times instead of relative
  --offline             never call the provider or a host
`)
	if a.Loop != "" {
		fmt.Fprintf(w, "\ntypical loop:  %s\n", a.Loop)
	}
	fmt.Fprint(w, "exit codes: 0 ok, 1 error, 2 usage, 3 problems found / changes pending / refused.\n")
	if a.Footer != "" {
		fmt.Fprint(w, a.Footer)
	}
}

// guardProtectedEnv refuses a mutating command on a protected environment
// unless --confirm names it. A missing or invalid inventory is not this
// guard's business; the command reports that itself.
func (c *Ctx) guardProtectedEnv() error {
	path := c.Inventory
	if path == "" {
		path = "infra.yaml"
	}
	inv, err := inventory.Load(path)
	if inv == nil || err != nil {
		return nil
	}
	env, err := inv.PickEnv(c.Env)
	if err != nil {
		return nil
	}
	return c.ConfirmProtected(env, inv.Environments[env].Protected)
}

// ConfirmProtected is the protected-environment check for commands whose
// target environment is not the --env one (a secret path, a host of another
// environment): exit 3 unless --confirm <env> or INFRA_CONFIRM=<env> was given.
func (c *Ctx) ConfirmProtected(env string, protected bool) error {
	if !protected || c.Confirm == env {
		return nil
	}
	return Problemsf("environment %s is protected; pass --confirm %s (or INFRA_CONFIRM=%s) to change it", env, env, env)
}
