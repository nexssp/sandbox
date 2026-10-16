# Nexss Sandbox

<small>Nexss Flow 🌀 ready</small>

<!-- project-status -->

[![CI](https://github.com/nexssp/sandbox/actions/workflows/ci.yml/badge.svg)](https://github.com/nexssp/sandbox/actions/workflows/ci.yml)
[![Latest tag](https://img.shields.io/github/v/tag/nexssp/sandbox?sort=semver&label=latest%20tag)](https://github.com/nexssp/sandbox/tags)
[![Go Reference](https://pkg.go.dev/badge/github.com/nexssp/sandbox.svg)](https://pkg.go.dev/github.com/nexssp/sandbox)
[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)

<!-- /project-status -->

Nexss Sandbox provides a Go `sandbox.Engine` contract for command execution, workspace file access, and reset/close lifecycle. Docker, Podman, in-process, and mock engines implement the same interface; their isolation properties differ.

> **Important:** `StaticPolicy` validates profiles, commands, environment keys, and file writes; it is not an operating-system security boundary. The `inprocess` engine executes commands directly on the host and is for trusted use only. The Docker and Podman adapters have known enforcement gaps and have not been verified against a real runtime here. Do not treat this package as hardened isolation for untrusted code.

## Architecture

```
Go host / Nexss Flow
          │
          ▼
  sandbox.Engine contract
  ├── docker      container-backed workspace
  ├── podman      Podman-backed workspace
  ├── inprocess   direct host execution; trusted use only
  └── mock        deterministic test double
          │
          ├── command execution and bounded results
          └── workspace file operations and session lifecycle
```

## Install

Requires **Go 1.26.9 or newer**.

```
go get github.com/nexssp/sandbox@latest
```

The repository depends on Nexss Flow and Nexss Kernel for its Flow bundle and action integration.

## Engines

| Engine | Intended use | Notes |
| --- | --- | --- |
| `docker` | Container-backed command execution | Uses a long-lived workspace container; current enforcement caveats apply. |
| `podman` | Podman-backed execution | Supports rootless setups; current enforcement caveats apply. |
| `inprocess` | Trusted local command execution | Runs programs on the host; profile resource limits do not isolate the process. |
| `mock` | Unit tests and deterministic test fixtures | A pure-Go fake; it recognizes a small set of commands such as `ls`, `cat`, `go`, and `gofmt`. |

## Go API

The common `sandbox.Engine` contract covers command execution, workspace file operations, and session lifecycle. `Profile.ApplyDefaults` supplies request limits and execution defaults; direct callers should explicitly validate requests with a policy before running them. For example:

```go
import (
    "context"
    "fmt"

    "github.com/nexssp/sandbox"
    "github.com/nexssp/sandbox/docker"
)

func runTests(ctx context.Context) error {
    engine, err := docker.NewSandboxEngine(docker.Config{
        WorkspaceDir: ".sandbox",
        DefaultImage: "golang:1.26-alpine",
    })
    if err != nil {
        return err
    }
    defer engine.Close()

    profile := sandbox.Profile{
        Name:               "builder",
        Image:              "golang:1.26-alpine",
        MemoryMB:           2048,
        CPUs:               2.0,
        PidsLimit:          512,
        NetworkMode:        "none",
        ReadOnlyRootFS:     true,
        AllowedExecutables: []string{"go", "git", "gofmt"},
    }
    profile.ApplyDefaults()

    policy := sandbox.StaticPolicy{}
    if err := policy.ValidateProfile(profile); err != nil {
        return err
    }
    command := sandbox.Command{Argv: []string{"go", "test", "./..."}}
    if err := policy.ValidateCommand(profile, command); err != nil {
        return err
    }

    result, err := engine.Run(ctx, "session-1", profile, command)
    if err != nil {
        return err
    }
    if result.ExitCode != 0 {
        return fmt.Errorf("go test failed with exit code %d: %s", result.ExitCode, result.Stderr)
    }
    return nil
}
```

`ExecutionResult` reports `ExitCode`, `Stdout`, `Stderr`, `Duration`, and whether output was `Truncated`. The Flow `sandbox.exec` action also returns `passed` and a string `duration`. An engine's `Run` method does not itself apply `StaticPolicy`; the Flow action validates its requests, while direct Go callers are responsible for applying policy checks.

## Nexss Flow 🌀 integration

The `nexssflow` bundle provides the generic `sandbox.exec` action and the `@sandbox NAME { ... }` directive for named profiles (for example, `sandbox.builder`). `sandbox.exec` uses the profile configured in `@require`; named actions use their own declared profile. The default static policy requires a profile image and executable allowlist. Bundle options also select the engine, workspace, cache, environment allowlist, and policy behavior.

The `as <alias>` form of `@require` is supported. This Docker example shows the generic action and a named profile; it requires an available Docker runtime. Keep the named profile image aligned with the global image because the current adapters reuse a long-lived workspace container and do not switch its image per profile.

```
@require github.com/nexssp/sandbox/nexssflow as sb {
  engine: "docker",
  workspace: ".sandbox",
  image: "golang:1.26-alpine",
  allowed_executables: "go, git, gofmt",
  allowed_env_keys: "GOCACHE, GOPROXY"
}

@sandbox builder {
  image: "golang:1.26-alpine",
  memory_mb: 2048,
  cpus: 2.0,
  allowed_executables: "go, git, gofmt",
  allowed_env_keys: "GOCACHE, GOPROXY"
}

{ command: "go", args: ["test", "./..."] } -> sb.builder
{ command: "go", args: ["test"] } -> sb.exec
```

This compact integration example uses the deterministic mock engine. It exercises both the named and generic actions without starting a container or running a host command:

```
@require github.com/nexssp/sandbox/nexssflow as sb {
  engine: "mock",
  workspace: ".sandbox_flow",
  enforce_policy: "false"
}
@sandbox builder { image: "golang:1.26-alpine", memory_mb: 2048, cpus: 2.0 }

{ command: "go", args: ["test", "./..."] } -> sb.builder
{ command: "go", args: ["test"] } -> sb.exec
```

The result includes `exit_code`, `stdout`, `stderr`, `duration`, `truncated`, and `passed`. With the default policy enabled, the global `@require` profile used by `sb.exec` must also set `image` and `allowed_executables`. `enforce_policy: "false"` is shown only to keep the mock fixture minimal; do not disable policy for untrusted inputs. The `mock` engine is a deterministic test double, not a command-execution sandbox.

### Workspace files and typed references

Host-side workspace reads and writes use `WorkspaceFS` backed by Go's `os.Root`, confining paths and installing writes atomically. Flow `sandbox.exec` accepts `files` as a map from workspace-relative destination paths to typed `xfile.Ref` values (`nexssflow.BlobRef` is an alias); it does not take inline file contents as file references. Provider and object IDs are opaque and are never interpreted as local paths.

File references remain fail-closed unless the host explicitly supplies an authorized `xfile.Resolver`, for example with `nexssflow.BundleWithFileResolver`. The adapter checks caller/tenant scope, validates the provider/object identity returned by the resolver, and checks any requested version, size, and SHA-256 digest. It bounds each file by `MaxFileBytes`, stages and verifies resolved content before installing it into the workspace, and rejects invalid destinations. The standard `@require` bundle does not automatically connect Storage providers; without a resolver, requests containing file references return unavailable.

> **WIP — automatic file-provider wiring:** `BundleWithFileResolver` supports a host-injected resolver, but ordinary `@require` does not yet connect Storage providers automatically. File references fail closed until the host supplies an authorized resolver.

Runnable ecosystem examples now live in the [Nexss examples repository](https://github.com/nexssp/examples).

## Policy and enforcement boundary

`StaticPolicy` is the default policy used by the Flow bundle. It rejects:

- Profiles without a name, image, positive resource and request bounds, or an executable allowlist; profiles must use `NetworkMode: "none"` and a read-only root filesystem.

- Commands with no argv, too many arguments, an executable path rather than a bare name, an executable outside the profile allowlist, NUL bytes, or an argument longer than `MaxCommandArgBytes`.

- Environment entries that are malformed, contain NUL bytes, or use a key not listed in `AllowedEnvKeys`.

- File writes with an empty or absolute path, a `..` path component, a negative size, or a payload larger than `MaxFileBytes`.

`PermissivePolicy` disables these checks. In Flow, `enforce_policy: "false"` selects it; use that only with trusted, hermetic fixtures whose inputs have already been vetted. Direct Go callers must invoke the policy checks themselves if they need request validation.

> **Enforcement boundary:** Policy checks validate requests; they do not isolate command execution. The host-side `ReadFile` and `WriteFile` operations use `WorkspaceFS` backed by Go's `os.Root`, rejecting lexical and symlink escapes and installing writes atomically. The Flow `sandbox.exec` action applies `MaxWallTime` to each run and caps a requested timeout at the profile limit. Docker's normal `Engine.Run` bounds captured stdout and stderr independently by `MaxOutputBytes`; that bound does not cover Docker `ExecAdvanced` or Podman's output capture. Docker and Podman mount the host workspace read-write, reuse a long-lived container, may ignore per-profile resource-update failures, and do not switch the container image for each named profile. Runtime-backed isolation has not been verified here. Do not use `inprocess` for untrusted commands or treat Docker/Podman as hardened isolation until the remaining gaps are closed and tested against real runtimes.

## Profile defaults

`Profile.ApplyDefaults()` fills in defaults for fields used by the engines. Explicit resource values in your profile override the corresponding positive-valued defaults; `ReadOnlyRootFS` is set to `true`.

| Field | Default |
| --- | --- |
| `MemoryMB` | `1024` |
| `CPUs` | `1.0` |
| `NetworkMode` | `"none"` |
| `User` | Current effective `<uid>:<gid>` (or `1000:1000` when unavailable) |
| `Workspace` | `"/workspace"` |
| `PidsLimit` | `64` |
| `MaxWallTime` | `2m` |
| `MaxOutputBytes` | `1 MiB` |
| `MaxFileBytes` | `5 MiB` |
| `MaxCommandArgs` | `64` |
| `MaxCommandArgBytes` | `32 KiB` |
| `ReadOnlyRootFS` | `true` |

These are request/profile defaults, not proof that a backend enforces those restrictions as an OS-level boundary.

## Engine contract

Every engine implements the common lifecycle and workspace interface:

```go
type Engine interface {
    Name() string
    Run(ctx context.Context, sessionID string, profile Profile, command Command) (ExecutionResult, error)
    WriteFile(ctx context.Context, sessionID string, profile Profile, relativePath string, content []byte) error
    ReadFile(ctx context.Context, sessionID string, profile Profile, relativePath string) ([]byte, error)
    Reset(ctx context.Context, sessionID string) error
    Close() error
}
```

`Provider` is an optional extension for filesystem introspection (`Stat`, `ListDir`, `OpenStream`) and long-lived background processes (`SpawnBackground`). The bundled engines do not implement this cross-engine interface today; use engine-specific APIs where available.

## Packages

| Package | Purpose |
| --- | --- |
| [`sandbox`](.) | Engine, profile, command/result types, policies, mock and in-process engines, and confined workspace operations. |
| [`docker`](docker/) | Docker engine and workspace cache support. |
| [`podman`](podman/) | Podman engine adapter. |
| [`nexssflow`](nexssflow/) | Flow bundle, named sandbox directive, execution action, and embedded fixtures. |

## Development

Install [Task](https://taskfile.dev), then run the repository's test task or CI gate:

```
task test
task test -- ./docker
task ci
```

`task test` runs the short test suite; pass a package after `--` to limit it. `task ci` runs lint and uncached race tests, as defined in `Taskfile.yml`. The tests use fakes or harmless local fixtures and do not require a model or container daemon. Passing tests does not verify Docker or Podman isolation against a real runtime.

## Related projects

- [Nexss Flow](https://github.com/nexssp/flow) — Flow language and runtime.

- [Nexss Kernel](https://github.com/nexssp/kernel) — typed actions and request context.

- [Nexss Storage](https://github.com/nexssp/storage) — storage adapters that can provide scoped file references.
