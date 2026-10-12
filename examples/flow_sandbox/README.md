# Flow + Sandbox examples

These five `.nflow` files demonstrate the `github.com/nexssp/sandbox/nexssflow` Flow integration. They use the released Flow v0.20.3 CLI and this sandbox module from its declared import path. Run them from the Sandbox module root after the sandbox module source is available to Go's module resolver; a paired local `go.work` is not required.

## Run the examples

Requirements: Go 1.26 or later, network access for Go module resolution, plus `node` and `python` on `PATH` for the commands used by these examples.

Run each command from the Sandbox module root:

```bash
go run github.com/nexssp/flow/cmd/nflow@v0.20.3 run examples/flow_sandbox/01_hello_sandbox.nflow -v
go run github.com/nexssp/flow/cmd/nflow@v0.20.3 run examples/flow_sandbox/02_polyglot_pipeline.nflow -v
go run github.com/nexssp/flow/cmd/nflow@v0.20.3 run examples/flow_sandbox/03_security_profiles.nflow -v
go run github.com/nexssp/flow/cmd/nflow@v0.20.3 run examples/flow_sandbox/04_parallel_matrix.nflow -v
go run github.com/nexssp/flow/cmd/nflow@v0.20.3 run examples/flow_sandbox/05_self_healing_loop.nflow -v
```

The five examples cover file injection and execution, a Node-to-Python pipeline, static policy validation, parallel commands, and a retry/repair loop. The workspaces are `.sandbox_01` through `.sandbox_05` under the Sandbox project root; remove them after a run if you do not need their contents.

## Host execution and container isolation

All five examples select the `inprocess` engine. It launches the requested programs directly on the host and writes injected files into the configured workspace on the host. Profile values such as memory, CPU, PID limits, networking, or read-only-root settings do **not** create or enforce an OS/container security boundary in this mode. Chapter 3 demonstrates policy validation only; it is not an isolation test.

Docker and Podman are separate container-backed engines. These examples do not exercise them, and their current adapters have known enforcement gaps and have not been verified against a real container runtime for this review. Do not treat them as hardened for untrusted workloads or infer container-isolation test coverage from this showcase. See the [Sandbox policy and enforcement notes](../../README.md#policy) for the current caveats.
