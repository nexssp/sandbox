package nexssflow_test

import (
	"context"
	"strings"
	"testing"

	"github.com/nexssp/flow/compiler"
	"github.com/nexssp/flow/extensions/require"
	"github.com/nexssp/flow/native"
	"github.com/nexssp/flow/runner"
)

// TestSandboxBundle_EndToEnd_MockEngine wires up the full Flow
// runtime (preprocess → @require resolution → materialize → compile →
// run) and verifies that a .nflow file using
//
//	@require github.com/nexssp/sandbox/nexssflow { engine: "mock" }
//	@sandbox builder { image: "golang:1.26-alpine" }
//	{ command: "go", args: ["test", "./..."] } -> sandbox.builder
//
// produces a sandbox.builder action that runs the command through the
// mock engine and returns exit_code 0, stdout="PASS\n...", and
// passed=true.
func TestSandboxBundle_EndToEnd_MockEngine(t *testing.T) {
	t.Parallel()

	src := `@require github.com/nexssp/sandbox/nexssflow { engine: "mock", workspace: ".sandbox_e2e_mock", enforce_policy: "false" }

@sandbox builder { image: "golang:1.26-alpine", memory_mb: 1024 }

{ command: "go", args: ["test", "./..."] } -> sandbox.builder
`

	cfg := buildConfig(t, src)
	ctx := context.Background()

	ex, err := runner.Execute(ctx, cfg, src, "e2e_mock.nflow", map[string]any{})
	if err != nil {
		t.Fatalf("execute: %v", err)
	}

	out, ok := ex.Output.(map[string]any)
	if !ok {
		t.Fatalf("output type = %T, want map[string]any", ex.Output)
	}
	if exitCode, _ := out["exit_code"].(int); exitCode != 0 {
		t.Fatalf("exit_code = %d, want 0", exitCode)
	}
	if passed, _ := out["passed"].(bool); !passed {
		t.Fatal("passed = false, want true")
	}
	stdout, _ := out["stdout"].(string)
	if !strings.Contains(stdout, "PASS") {
		t.Fatalf("stdout = %q, want PASS somewhere", stdout)
	}
}

// TestSandboxBundle_EndToEnd_Alias verifies the `as <alias>` feature
// of @require: when the user writes
//
//	@require github.com/nexssp/sandbox/nexssflow as sb { engine: "mock" }
//
// the generic exec action is reachable as `sb.exec` in addition to
// `sandbox.exec`.
func TestSandboxBundle_EndToEnd_Alias(t *testing.T) {
	t.Parallel()

	src := `@require github.com/nexssp/sandbox/nexssflow as sb { engine: "mock", workspace: ".sandbox_e2e_alias", enforce_policy: "false" }

{ command: "go", args: ["test", "./..."] } -> sb.exec
`

	cfg := buildConfig(t, src)
	ctx := context.Background()

	ex, err := runner.Execute(ctx, cfg, src, "e2e_alias.nflow", map[string]any{})
	if err != nil {
		t.Fatalf("execute: %v", err)
	}
	out, ok := ex.Output.(map[string]any)
	if !ok {
		t.Fatalf("output type = %T", ex.Output)
	}
	if passed, _ := out["passed"].(bool); !passed {
		t.Fatal("passed = false, want true")
	}
}

func TestSandboxBundle_EndToEnd_NamedProfileAlias(t *testing.T) {
	t.Parallel()

	src := `@require github.com/nexssp/sandbox/nexssflow as sb { engine: "mock", workspace: ".sandbox_e2e_named_alias", enforce_policy: "false" }

@sandbox builder { image: "alpine:latest" }

{ command: "go", args: ["test"] } -> sb.builder
`

	cfg := buildConfig(t, src)
	ex, err := runner.Execute(context.Background(), cfg, src, "e2e_named_alias.nflow", map[string]any{})
	if err != nil {
		t.Fatalf("execute: %v", err)
	}
	out, ok := ex.Output.(map[string]any)
	if !ok {
		t.Fatalf("output type = %T, want map[string]any", ex.Output)
	}
	if passed, _ := out["passed"].(bool); !passed {
		t.Fatal("passed = false, want true")
	}
}

func TestSandboxBundle_EndToEnd_GenericStaticAllowlist(t *testing.T) {
	t.Parallel()

	src := `@require github.com/nexssp/sandbox/nexssflow as sb { engine: "mock", workspace: ".sandbox_e2e_generic_static", image: "alpine:latest", allowed_executables: "go, git", enforce_policy: "true" }

{ command: "go", args: ["test"] } -> sb.exec
`

	cfg := buildConfig(t, src)
	ex, err := runner.Execute(context.Background(), cfg, src, "e2e_generic_static.nflow", map[string]any{})
	if err != nil {
		t.Fatalf("execute: %v", err)
	}
	out, ok := ex.Output.(map[string]any)
	if !ok {
		t.Fatalf("output type = %T, want map[string]any", ex.Output)
	}
	if passed, _ := out["passed"].(bool); !passed {
		t.Fatal("passed = false, want true")
	}
}

// TestSandboxBundle_EndToEnd_InProcessEngine runs a real command
// through the in-process engine to verify the engine honors
// Profile.Workspace and produces a correct exit_code/stdout.
//
// `go version` is used rather than `echo`: `echo` is a shell builtin
// on Windows and has no executable in PATH, so the test would fail on
// Windows hosts. `go` is guaranteed present because the test suite
// itself was compiled by the Go toolchain.
func TestSandboxBundle_EndToEnd_InProcessEngine(t *testing.T) {
	t.Parallel()

	src := `@require github.com/nexssp/sandbox/nexssflow { engine: "inprocess", workspace: ".sandbox_e2e_inprocess", enforce_policy: "false" }

{ command: "go", args: ["version"] } -> sandbox.exec
`

	cfg := buildConfig(t, src)
	ctx := context.Background()

	ex, err := runner.Execute(ctx, cfg, src, "e2e_inprocess.nflow", map[string]any{})
	if err != nil {
		t.Fatalf("execute: %v", err)
	}
	out, ok := ex.Output.(map[string]any)
	if !ok {
		t.Fatalf("output type = %T", ex.Output)
	}
	exitCode, _ := out["exit_code"].(int)
	if exitCode != 0 {
		stderr, _ := out["stderr"].(string)
		t.Fatalf("exit_code = %d, want 0; stderr=%q", exitCode, stderr)
	}
	stdout, _ := out["stdout"].(string)
	if !strings.Contains(stdout, "go version") {
		t.Fatalf("stdout = %q, want 'go version' somewhere", stdout)
	}
}

// TestSandboxBundle_EndToEnd_NamedSandboxWithFiles verifies the
// sandbox.exec action accepts inline files and writes them into the
// workspace before running the command.
func TestSandboxBundle_EndToEnd_NamedSandboxWithFiles(t *testing.T) {
	t.Parallel()

	src := `@require github.com/nexssp/sandbox/nexssflow { engine: "mock", workspace: ".sandbox_e2e_files", enforce_policy: "false" }

@sandbox runner { image: "alpine:latest" }

{
  command: "cat",
  args: ["hello.txt"],
  files: { "hello.txt": "hello from file" }
} -> sandbox.runner
`

	cfg := buildConfig(t, src)
	ctx := context.Background()

	ex, err := runner.Execute(ctx, cfg, src, "e2e_files.nflow", map[string]any{})
	if err != nil {
		t.Fatalf("execute: %v", err)
	}
	out, ok := ex.Output.(map[string]any)
	if !ok {
		t.Fatalf("output type = %T", ex.Output)
	}
	stdout, _ := out["stdout"].(string)
	if !strings.Contains(stdout, "hello from file") {
		t.Fatalf("stdout = %q, want 'hello from file'", stdout)
	}
}

// buildConfig preprocesses src to extract @require declarations,
// resolves them against the registry, and builds a runner.Config that
// includes the sandbox bundle's directives and libraries alongside
// every native Flow bundle (so projection, runtime, modifiers, etc.
// are all available).
func buildConfig(t *testing.T, src string) runner.Config {
	t.Helper()
	ctx := context.Background()

	// Start from the native bundles so all standard extensions
	// (projection for `{}`, runtime for `noop`/`debug`, modifiers,
	// directives, etc.) are present.
	allBundles := native.Bundles()

	// Run preprocess with the full directive table to collect
	// @require declarations.
	var extraDirectives []compiler.Directive
	for i := range allBundles {
		extraDirectives = append(extraDirectives, allBundles[i].Directives...)
	}
	dt := compiler.NewDirectiveTable(extraDirectives...)
	_, meta, err := compiler.Preprocess(ctx, dt, src, "test.nflow")
	if err != nil {
		t.Fatalf("preprocess: %v", err)
	}

	reqs := require.FromMeta(meta)
	if len(reqs) == 0 {
		t.Fatal("no @require declarations parsed")
	}

	bundles, err := require.ResolveBundles(reqs)
	if err != nil {
		t.Fatalf("resolve bundles: %v", err)
	}

	// Append the resolved bundles (e.g. sandbox) to the native set.
	allBundles = append(allBundles, bundles...)

	cfg, err := runner.BuildConfig(allBundles)
	if err != nil {
		t.Fatalf("build config: %v", err)
	}
	return cfg
}
