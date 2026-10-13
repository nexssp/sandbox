# Flow/Sandbox host integration

The `.nflow` example files are in the parent [`examples`](../README.md) directory. They use Flow v0.28.1 and the Sandbox module's declared import path.

Examples 06–07 demonstrate host-supplied typed `BlobRef` values in `files` and require an authorized `xfile.Resolver`. The host can inject one through `nexssflow.BundleWithFileResolver`, or let Flow v0.28.1 compose provider-scoped resolvers from bundles in `runner.BuildConfig`. The combined static `@embed` plus Storage path through `sandbox.exec` is covered by the Sandbox end-to-end test; the test uses a Storage test resolver, not a production backend.

The examples that select `inprocess` execute commands directly on the host. This mode is suitable only for trusted demonstrations and does not provide process or filesystem isolation. Docker and Podman examples are not runtime-isolation tests; see the [Sandbox policy and enforcement notes](../../README.md#policy).
