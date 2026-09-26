# infra-shared

The Go module a family of small infrastructure CLIs is built on: one
inventory file, plan/apply tools that never prompt, `--json` everywhere,
exit codes that mean something, usable by a person and by an agent alike.
Standard library plus `gopkg.in/yaml.v3`. It holds the conventions, not the
tools: nothing in here talks to a cloud, deploys or backs up anything.

| package | what |
|---|---|
| `cli` | command skeleton: global flags (`--inventory`, `--env`, `--json`, `--utc`, `--offline`), positional-anywhere flag parsing, exit codes 0/1/2/3, `error:` vs `{"error":..}` rendering, tables, relative times, automatic audit records for mutating commands |
| `inventory` | `infra.yaml`: types, strict parsing, validation, resolution of host addresses from a provider CLI (`<command> status --json`), ssh routes through jump hosts, the embedded reference/example/JSON schema |
| `sshx` | run scripts on a host through the system `ssh` along a route (`-J` for jump hosts), atomic file put, per-host lock |
| `audit` | one JSON line per mutating command in `~/.local/state/infra/audit.jsonl` |
| `token` | ed25519-signed, short-lived, scoped tokens (`INFRA_TOKEN`) and the guard every tool calls; `GuardPolicy` adds policy.yaml |
| `policy` | policy.yaml: `deny` and `approve` scope patterns for token holders |
| `approval` | the store of gated calls waiting for an operator: ask, approve, deny, single use |

## Using it from a tool

```
require github.com/timokoenig/infra-shared v0.1.0
```

```go
import (
    "github.com/timokoenig/infra-shared/cli"
    "github.com/timokoenig/infra-shared/inventory"
)
```

A tool builds a `cli.App`, adds `cli.Command`s and calls `Main`.

While the module is not tagged yet, or when changing it together with a
tool, point the tool at a sibling checkout instead:

```
replace github.com/timokoenig/infra-shared => ../infra-shared
```

## Releasing

A release is a git tag. There is nothing to build.

```sh
make test
git tag v0.1.0 && git push origin v0.1.0
```

Then in each tool: `go get github.com/timokoenig/infra-shared@v0.1.0 && go mod
tidy`. Below v1 there are no compatibility promises; a change that breaks a
tool is fine as long as the tool moves to the new tag in the same change.

## Development

```sh
make test     # vet + tests with -race
make fmt
```
