# nexss-sandbox

A command-execution library with pluggable runtimes; isolation guarantees depend on the selected backend.
The same `sandbox.Engine` interface is implemented by four backends:

| Engine     | Use case                                                        |
| ---------- | --------------------------------------------------------------- |
| `docker`   | Docker-backed container execution; current adapter caveats apply. |
| `podman`   | Rootless Podman-backed execution; current adapter caveats apply. |
| `inprocess`| Trusted tests only; runs commands directly on the host.       |
| `mock`     | Pure-Go fake for tests; recognises `ls`, `cat`, `go`, `gofmt`. |

The sandbox is exposed to [Nexss Flow](https://pkg.go.dev/github.com/nexssp/flow) via the
`nexssflow` subpackage: a `.nflow` file pulls the sandbox in with a
single `@require` line and gets a `sandbox.exec` action plus the
`@sandbox NAME { ... }` directive for declaring named, pre-profiled
sandboxes.

## Layout

```
sandbox/
├── sandbox.go          Engine interface, Profile, Command, ExecutionResult
├── policy.go           StaticPolicy + PermissivePolicy
├── provider.go         Optional Provider extension (Stat/ListDir/Spawn)
├── inprocess.go        Host execution engine (CI / fallback)
├── mock.go             In-memory fake for unit tests
├── workspace.go        WorkspaceFS — escape-proof os.Root wrapper
├── workspace_actions.go  read_file / write_file / edit_file actions
├── system_tools.go     fs.read / fs.write / fs.patch / sandbox.exec
├── library.go          ai/sandbox action library (workspace ops)
├── docker/
│   ├── docker.go       DockerSandboxEngine — long-lived workspace container
│   └── cache.go        CacheManager — docker commit/save/load
├── podman/
│   └── podman.go       PodmanSandboxEngine — rootless parity with docker
└── nexssflow/
    ├── library.go      Flow Bundle factory + GlobalOptions
    ├── directive.go    @sandbox NAME { ... } declaration handler
    ├── materialize.go  Mounts sandbox.<name> actions on the resolver
    ├── exec.go         runAndMerge — the shared exec implementation
    ├── decl.go         SandboxDecl struct
    ├── errors.go       errUnknownEngine
    ├── selftest.go     SelfTest features for `nflow self test`
    └── nflows/         Embedded *.nflow fixtures
```

## Usage from a .nflow file

```nflow
@require github.com/nexssp/sandbox/nexssflow {
    engine:                "docker",
    workspace:             ".sandbox",
    image:                 "golang:1.26-alpine",
    allowed_executables:   "go, git, gofmt",
    allowed_env_keys:      "GOCACHE, GOPROXY",
    no_cache:              false
}

@sandbox builder { image: "golang:1.26-alpine", memory_mb: 2048, cpus: 2.0, allowed_executables: "go, git, gofmt", allowed_env_keys: "GOCACHE, GOPROXY" }

{ command: "go", args: ["test", "./..."] } -> sandbox.builder
```

The `as <alias>` feature of `@require` is honored. With the default static policy, generic `sandbox.exec` requires both a global `image` and `allowed_executables` option:

```nflow
@require github.com/nexssp/sandbox/nexssflow as sb { engine: "mock", image: "alpine:latest", allowed_executables: "go" }

{ command: "go", args: ["test"] } -> sb.exec
```

## Usage as a Go library

```go
import (
    "github.com/nexssp/sandbox"
    "github.com/nexssp/sandbox/docker"
)

engine, err := docker.NewDockerSandboxEngine(docker.Config{
    WorkspaceDir:  ".sandbox",
    DefaultImage:  "golang:1.26-alpine",
})
if err != nil { return err }
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
if err := policy.ValidateProfile(profile); err != nil { return err }

cmd := sandbox.Command{Argv: []string{"go", "test", "./..."}}
if err := policy.ValidateCommand(profile, cmd); err != nil { return err }

result, err := engine.Run(ctx, "session-1", profile, cmd)
// result.ExitCode, result.Stdout, result.Stderr, result.Duration
```

## Storage-backed file references

Flow `sandbox.exec` accepts `files` as `map[string]nexssflow.BlobRef` (an alias of `kernel/xfile.Ref`), not inline file contents. Each map key is a workspace-relative destination; each value is an opaque provider reference. The `Provider` and `ID` fields are never interpreted as a local path.

File references remain fail-closed unless a resolver is explicitly configured. A host may inject one directly with `nexssflow.BundleWithFileResolver`; with Flow v0.28.1, provider-scoped resolvers registered by other bundles are composed by `runner.BuildConfig` and exposed through the action context, so the Sandbox bundle can use the combined filesystem and Storage resolver without a custom multiplexer.

```go
bundle := nexssflow.BundleWithFileResolver(flowOptions, resolver)
```

The resolver receives the action context. Sandbox checks authenticated caller and tenant scope with `xfile.ScopeFromContext` before opening a reference, then verifies the returned provider/object identity, optional version and expected size, the actual byte count, and the `sha256:<hex>` digest. It streams through a bounded buffer into a private temporary file, removes partial data on cancellation or error, and only then installs the verified file through a confined, atomic workspace write. `MaxFileBytes` is enforced on each resolved file. The normal registry factory (`Bundle`) has no resolver and returns `Unavailable` if a request contains file refs; there is no implicit storage-provider lookup.

Examples 06–07 show host-supplied provider references. Static `@embed` plus Storage staging through `sandbox.exec` is covered by `TestSandboxBundle_EndToEnd_StagesStaticEmbedAndStorageRef` in [`nexssflow/end_to_end_test.go`](nexssflow/end_to_end_test.go).

**Flow v0.28.1 static embed + Storage integration is verified.** The published `extensions/embed` bundle creates typed `xfile.Ref` values from a declared `fs.FS` and registers an FS-backed resolver. `runner.BuildConfig` composes it with provider-scoped Storage resolvers and exposes the composite through the action context; the Sandbox adapter uses that context resolver when no direct resolver was injected. The end-to-end test executes `@embed logo`, passes the resulting static ref and a Storage BlobRef through `sandbox.exec`, and checks both staged payloads. Storage is represented by a deterministic test resolver; this does not exercise a production Storage service or a real container runtime.

## Policy

`StaticPolicy` is the default. It rejects:

- Profiles with `NetworkMode != "none"` (host networking).
- Profiles with `ReadOnlyRootFS == false` (writable rootfs).
- Profiles with any of `MemoryMB`, `CPUs`, `PidsLimit`, `MaxWallTime`,
  `MaxOutputBytes`, `MaxFileBytes`, `MaxCommandArgs`, or
  `MaxCommandArgBytes` set to zero.
- Profiles with no `AllowedExecutables`.
- Commands whose `Argv[0]` is not on the allowlist.
- Commands whose `Argv[0]` contains a path separator (`/` or `\`).
- Commands whose argv contains a NUL byte or exceeds `MaxCommandArgBytes`.
- Environment entries that are malformed, contain NUL bytes, or use a key not listed in `AllowedEnvKeys`.
- Writes whose path is absolute, contains `..`, or exceeds
  `MaxFileBytes`.

`PermissivePolicy` disables every check. Use it only in trusted, hermetic
CI environments where the caller has already vetted the inputs.

The `@require` option `enforce_policy: "false"` switches the bundle to
`PermissivePolicy`. The default is `"true"`.

> **Enforcement boundary:** `StaticPolicy` validates requests; it is not an OS security boundary, and direct callers must invoke the policy checks themselves. The host-side `ReadFile`/`WriteFile` methods use `WorkspaceFS` backed by Go's `os.Root`, rejecting lexical and symlink escapes and enforcing `MaxFileBytes`; writes are installed atomically from a temporary file within the workspace. This confines file operations but does not isolate command execution. `inprocess` runs commands directly on the host and must only be used with trusted commands. The Flow `sandbox.exec` action applies `MaxWallTime` to every run and caps a caller-supplied timeout at that profile limit. Docker `Engine.Run` bounds captured stdout and stderr independently by `MaxOutputBytes`; environment keys are checked against `AllowedEnvKeys`. Those controls do not cover Docker `ExecAdvanced` or Podman's output capture. Docker and Podman mount the host workspace read-write; both reuse a long-lived container, ignore per-profile resource-update failures, and do not switch the container image for each named profile. Runtime-backed isolation was not verified here, so do not treat Docker or Podman as hardened for untrusted workloads until the remaining gaps are closed and tested against real runtimes.

## Profile defaults

`Profile.ApplyDefaults()` fills in safe values for every field the
engines consult:

| Field                | Default        |
| -------------------- | -------------- |
| `MemoryMB`           | `1024`         |
| `CPUs`               | `1.0`          |
| `NetworkMode`        | `"none"`       |
| `User`               | `<uid>:<gid>`  |
| `Workspace`          | `"/workspace"` |
| `PidsLimit`          | `64`           |
| `MaxWallTime`        | `2m`           |
| `MaxOutputBytes`     | `1 MiB`        |
| `MaxFileBytes`       | `5 MiB`        |
| `MaxCommandArgs`     | `64`           |
| `MaxCommandArgBytes` | `32 KiB`       |
| `ReadOnlyRootFS`     | `true`         |

## Engine contract

Every engine implements:

```go
type Engine interface {
    Name() string
    Run(ctx, sessionID, profile, command) (ExecutionResult, error)
    WriteFile(ctx, sessionID, profile, relativePath, content) error
    ReadFile(ctx, sessionID, profile, relativePath) ([]byte, error)
    Reset(ctx, sessionID) error
    Close() error
}
```

`Provider` is an optional extension for engines that also expose
filesystem introspection (`Stat`, `ListDir`, `OpenStream`) and
long-lived background processes (`SpawnBackground`). The bundled
engines do not implement it today; the interface is reserved for
A2A-worker engines that need cross-engine introspection.

## Flow showcase

The Flow integration examples are in [`examples`](examples/README.md). Examples 01–05 demonstrate command workflows; examples 06–07 demonstrate host-supplied BlobRefs. The module pins Flow v0.28.1 and Kernel v0.32.0.

Some examples select `inprocess`, which executes commands on the host. Use that backend only for trusted demonstrations; it does not isolate model-generated or other untrusted code. Docker and Podman remain unverified against a real container runtime for this review; see the enforcement boundary above.

## Testing

```bash
go test ./...
```

The unit and end-to-end tests use fake or harmless local fixtures; they do not require a live model or container daemon. Run this command from the module root with Go 1.26.9 or later. A passing test suite does not verify Docker or Podman isolation.
