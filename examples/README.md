# Flow + Sandbox examples

The seven `.nflow` examples live in this directory and exercise the `github.com/nexssp/sandbox/nexssflow` integration. Examples 01–05 use the released Flow v0.28.1 CLI; examples 06–07 show host-supplied typed file references and require an authorized resolver.

## Run the command examples

Requirements: Go 1.26.9 or later, network access for Go module resolution, plus `node` and `python` on `PATH` for the commands used by examples 01–05. Run from the Sandbox module root:

```bash
go run github.com/nexssp/flow/cmd/nflow@v0.28.1 run examples/01_hello_sandbox.nflow -v
go run github.com/nexssp/flow/cmd/nflow@v0.28.1 run examples/02_polyglot_pipeline.nflow -v
go run github.com/nexssp/flow/cmd/nflow@v0.28.1 run examples/03_security_profiles.nflow -v
go run github.com/nexssp/flow/cmd/nflow@v0.28.1 run examples/04_parallel_matrix.nflow -v
go run github.com/nexssp/flow/cmd/nflow@v0.28.1 run examples/05_self_healing_loop.nflow -v
```

Examples 06–07 are request shapes for host-authorized provider refs; run them from a host that injects an `xfile.Resolver` with `nexssflow.BundleWithFileResolver` or registers provider-scoped resolver bundles in the Flow runner. The actual static `@embed` plus Storage composition through `sandbox.exec` is verified by `TestSandboxBundle_EndToEnd_StagesStaticEmbedAndStorageRef` in `nexssflow/end_to_end_test.go`.

## Host execution and container isolation

The examples use the `inprocess` engine. It launches programs directly on the host and writes files into a host workspace. Profile limits such as memory, CPU, PID count, networking, or read-only-root settings do **not** create an OS/container security boundary in this mode. Use `inprocess` only for trusted demonstrations; do not use these examples to run untrusted code.

Docker and Podman are separate container-backed engines. These examples do not exercise them, and their current adapters have known enforcement gaps and have not been verified against a real runtime for this review. Do not treat them as hardened for untrusted workloads or infer container-isolation coverage from this showcase. See the [Sandbox policy and enforcement notes](../README.md#policy).
