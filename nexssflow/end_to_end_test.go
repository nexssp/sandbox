package nexssflow_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/nexssp/flow/compiler"
	embedext "github.com/nexssp/flow/extensions/embed"
	"github.com/nexssp/flow/extensions/require"
	"github.com/nexssp/flow/native"
	"github.com/nexssp/flow/runner"
	"github.com/nexssp/kernel/xctx"
	"github.com/nexssp/kernel/xerr"
	"github.com/nexssp/kernel/xfile"
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

// TestSandboxBundle_EndToEnd_RequiresExplicitFileResolver verifies that
// the registry-provided bundle does not resolve external refs implicitly.
func TestSandboxBundle_EndToEnd_RequiresExplicitFileResolver(t *testing.T) {
	t.Parallel()

	src := `@require github.com/nexssp/sandbox/nexssflow { engine: "mock", workspace: ".sandbox_e2e_files", enforce_policy: "false" }

@sandbox runner { image: "alpine:latest" }

{
  command: "go",
  args: ["version"],
  files: { "hello.txt": { Provider: "test-store", ID: "hello" } }
} -> sandbox.runner
`

	cfg := buildConfig(t, src)
	ctx := context.Background()

	_, err := runner.Execute(ctx, cfg, src, "e2e_files.nflow", map[string]any{})
	if kind := xerr.KindFrom(err); kind != xerr.KindUnavailable {
		t.Fatalf("error kind = %q, want %q (err %v)", kind, xerr.KindUnavailable, err)
	}
}

func TestSandboxBundle_EndToEnd_StagesStaticEmbedAndStorageRef(t *testing.T) {
	staticPayload := []byte("static embedded payload\n")
	storagePayload := []byte("storage blob payload\n")
	storageSum := sha256.Sum256(storagePayload)
	storageDigest := "sha256:" + hex.EncodeToString(storageSum[:])
	workspaceDir := t.TempDir()
	readerPath := filepath.Join(workspaceDir, "read_files.go")
	// This small Go helper reads staged files without relying on a Unix `cat` command.
	readerSource := `package main

import "os"

func main() {
	for _, name := range os.Args[1:] {
		data, err := os.ReadFile(name)
		if err != nil {
			panic(err)
		}
		if _, err := os.Stdout.Write(data); err != nil {
			panic(err)
		}
	}
}`
	if err := os.WriteFile(readerPath, []byte(readerSource), 0o600); err != nil {
		t.Fatal(err)
	}

	embedBundle, embedResolver := embedext.BundleWithFileResolver(fstest.MapFS{
		"assets/logo.txt": &fstest.MapFile{Data: staticPayload},
	}, "flow.static", 1024)
	if embedResolver == nil {
		t.Fatal("embed.BundleWithFileResolver returned a nil resolver")
	}

	storageRef := xfile.Ref{
		Provider:       "test.storage",
		ID:             "opaque-storage-id",
		Version:        "v1",
		ExpectedSize:   xfile.ExpectedSize(len(storagePayload)),
		ExpectedDigest: xfile.ExpectedDigest(storageDigest),
	}
	storageCalls := 0
	storageResolver := storageResolverFunc(func(_ context.Context, ref xfile.Ref) (io.ReadCloser, xfile.Info, error) {
		storageCalls++
		if ref != storageRef {
			return nil, xfile.Info{}, fmt.Errorf("storage ref = %#v, want %#v", ref, storageRef)
		}
		return io.NopCloser(strings.NewReader(string(storagePayload))), xfile.Info{
			Provider: ref.Provider,
			ID:       ref.ID,
			Version:  ref.Version,
			Size:     int64(len(storagePayload)),
			Digest:   storageDigest,
		}, nil
	})
	storageBundle := compiler.BundleWithFileResolver(compiler.Bundle{ID: "e2e-storage"}, storageRef.Provider, storageResolver)

	src := fmt.Sprintf(`@require github.com/nexssp/sandbox/nexssflow as sb { engine: "inprocess", workspace: %q, enforce_policy: "false" }
@embed logo "assets/logo.txt"

sb.exec @{
  command: "go",
  args: ["run", %q, "static", "storage"],
  files: {
    static: embed.logo,
    storage: {
      Provider: %q,
      ID: %q,
      Version: %q,
      ExpectedSize: %d,
      ExpectedDigest: %q
    }
  }
}
`, workspaceDir, readerPath, storageRef.Provider, storageRef.ID, storageRef.Version, storageRef.ExpectedSize, storageRef.ExpectedDigest)
	cfg := buildConfig(t, src, embedBundle, storageBundle)
	ctx := xctx.WithUserID(t.Context(), "e2e-caller")
	ctx = xctx.WithTenantID(ctx, "e2e-tenant")
	result, err := runner.Execute(ctx, cfg, src, "static_storage.nflow", nil)
	if err != nil {
		t.Fatalf("execute combined static embed and Storage staging: %v", err)
	}
	output, ok := result.Output.(map[string]any)
	if !ok {
		t.Fatalf("output type = %T, want map[string]any", result.Output)
	}
	if exitCode, _ := output["exit_code"].(int); exitCode != 0 {
		t.Fatalf("exit_code = %v, want 0; stderr=%q; full output=%#v", output["exit_code"], output["stderr"], output)
	}
	wantStdout := string(staticPayload) + string(storagePayload)
	if stdout, _ := output["stdout"].(string); stdout != wantStdout {
		t.Fatalf("stdout = %q, want both staged file payloads %q", stdout, wantStdout)
	}
	if storageCalls != 1 {
		t.Fatalf("Storage resolver calls = %d, want 1", storageCalls)
	}
}

// buildConfig preprocesses src to extract @require declarations,
// resolves them against the registry, and builds a runner.Config that
// includes the sandbox bundle's directives and libraries alongside
// every native Flow bundle (so projection, runtime, modifiers, etc.
// are all available).
func buildConfig(t *testing.T, src string, extraBundles ...compiler.Bundle) runner.Config {
	t.Helper()
	ctx := context.Background()

	// Start from the native bundles so all standard extensions
	// (projection for `{}`, runtime for `noop`/`debug`, modifiers,
	// directives, etc.) are present.
	allBundles := append(native.Bundles(), extraBundles...)

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

	reqs, err := require.FromMeta(meta)
	if err != nil {
		t.Fatalf("requirements: %v", err)
	}
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

type storageResolverFunc func(context.Context, xfile.Ref) (io.ReadCloser, xfile.Info, error)

func (resolver storageResolverFunc) Open(ctx context.Context, ref xfile.Ref) (io.ReadCloser, xfile.Info, error) {
	return resolver(ctx, ref)
}
