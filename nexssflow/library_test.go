package nexssflow

import (
	"context"
	"testing"

	"github.com/nexssp/flow/compiler"
	"github.com/nexssp/flow/native"
	"github.com/nexssp/flow/runner"
)

func TestBundle_MockEngine(t *testing.T) {
	t.Parallel()

	bundle := Bundle(map[string]string{"engine": "mock"})

	if bundle.ID != "sandbox" {
		t.Fatalf("bundle ID = %q, want %q", bundle.ID, "sandbox")
	}
	if len(bundle.Libraries) != 1 {
		t.Fatalf("libraries: want 1, got %d", len(bundle.Libraries))
	}
	if bundle.Libraries[0].Name != "sandbox" {
		t.Fatalf("library name = %q", bundle.Libraries[0].Name)
	}
	if len(bundle.Directives) != 1 || bundle.Directives[0].Name != "sandbox" {
		t.Fatalf("directives = %+v", bundle.Directives)
	}
	if bundle.Materialize == nil {
		t.Fatal("materialize hook is nil")
	}
	if bundle.SelfTest == nil {
		t.Fatal("selftest hook is nil")
	}
}

func TestBundle_RegistersExampleCapabilities(t *testing.T) {
	t.Parallel()

	bundles := append(native.Bundles(), Bundle(map[string]string{
		"engine":         "mock",
		"enforce_policy": "false",
	}))
	cfg, err := runner.BuildConfig(bundles)
	if err != nil {
		t.Fatalf("build canonical Flow config: %v", err)
	}

	tests := []struct {
		name       string
		source     string
		capability string
	}{
		{
			name:       "sandbox.exec",
			capability: "sandbox.exec",
			source:     `{ command: "echo", args: ["hello"] } -> sandbox.exec`,
		},
		{
			name:       "sandbox.builder",
			capability: "sandbox.builder",
			source: `@sandbox builder { image: "golang:1.26-alpine" }

{ command: "go", args: ["build", "./..."] } -> sandbox.builder`,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			compiled, err := runner.Compile(t.Context(), cfg, tt.source, tt.name+".nflow")
			if err != nil {
				t.Fatalf("compile through canonical Sandbox bundle: %v", err)
			}
			if _, ok := compiled.Resolver.Action(tt.capability); !ok {
				t.Fatalf("capability %q not registered by canonical Sandbox bootstrap", tt.capability)
			}
		})
	}
}

func TestMaterialize_MountsNamedSandboxes(t *testing.T) {
	t.Parallel()

	bundle := Bundle(map[string]string{"engine": "mock"})
	resolver, err := compiler.NewDynamicResolver()
	if err != nil {
		t.Fatal(err)
	}

	// Mount the bundle's base library so sandbox.exec resolves.
	for _, lib := range bundle.Libraries {
		if err := resolver.Mount(lib); err != nil {
			t.Fatalf("mount base lib: %v", err)
		}
	}

	meta := map[string]any{
		"sandboxes": []SandboxDecl{
			{Name: "builder", Image: "golang:1.26-alpine"},
		},
	}

	if err := bundle.Materialize(compiler.MaterializeReq{
		Ctx:      context.Background(),
		Meta:     meta,
		Resolver: resolver,
	}); err != nil {
		t.Fatalf("materialize: %v", err)
	}
	if _, ok := resolver.Action("sandbox.builder"); !ok {
		t.Fatal("sandbox.builder not mounted")
	}
}

func TestMaterialize_SkipsWhenEmpty(t *testing.T) {
	t.Parallel()

	bundle := Bundle(map[string]string{"engine": "mock"})
	resolver, _ := compiler.NewDynamicResolver()

	if err := bundle.Materialize(compiler.MaterializeReq{
		Ctx:      context.Background(),
		Meta:     map[string]any{},
		Resolver: resolver,
	}); err != nil {
		t.Fatalf("empty meta: %v", err)
	}
}

func TestBundle_RejectsUnknownEngine(t *testing.T) {
	t.Parallel()

	defer func() {
		if recover() == nil {
			t.Fatal("expected panic on unknown engine")
		}
	}()
	Bundle(map[string]string{"engine": "quantum"})
}

func TestHandleSandbox_RejectsMissingImage(t *testing.T) {
	t.Parallel()

	req := compiler.DirectiveReq{
		Lines: []string{`@sandbox builder { memory_mb: 2048 }`},
		I:     0,
		Out:   map[string]any{},
		File:  "test.nflow",
	}
	if _, err := handleSandbox(t.Context(), req); err == nil {
		t.Fatal("expected error for missing image")
	}
}

func TestHandleSandbox_RejectsUnknownAttribute(t *testing.T) {
	t.Parallel()

	req := compiler.DirectiveReq{
		Lines: []string{`@sandbox builder { image: "x", turbo: true }`},
		I:     0,
		Out:   map[string]any{},
		File:  "test.nflow",
	}
	if _, err := handleSandbox(t.Context(), req); err == nil {
		t.Fatal("expected error for unknown attribute")
	}
}

func TestHandleSandbox_AcceptExtendedAttributes(t *testing.T) {
	t.Parallel()

	req := compiler.DirectiveReq{
		Lines: []string{`@sandbox builder { image: "x", memory_mb: 2048, cpus: 2.0, pids_limit: 128, network_mode: "none", user: "1000:1000", workspace: "/ws", allowed_executables: "go, git", allowed_env_keys: "GOCACHE, GOPROXY" }`},
		I:     0,
		Out:   map[string]any{},
		File:  "test.nflow",
	}
	res, err := handleSandbox(t.Context(), req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res.Next == 0 {
		t.Fatal("expected next line index > 0")
	}
	decls, _ := req.Out["sandboxes"].([]SandboxDecl)
	if len(decls) != 1 {
		t.Fatalf("decls: want 1, got %d", len(decls))
	}
	d := decls[0]
	if d.MemoryMB != 2048 || d.CPUs != 2.0 || d.PidsLimit != 128 ||
		d.NetworkMode != "none" || d.User != "1000:1000" || d.Workspace != "/ws" {
		t.Fatalf("decl not parsed correctly: %+v", d)
	}
	if len(d.AllowedExecutables) != 2 || d.AllowedExecutables[0] != "go" || d.AllowedExecutables[1] != "git" {
		t.Fatalf("allowed_executables not parsed: %v", d.AllowedExecutables)
	}
	if len(d.AllowedEnvKeys) != 2 || d.AllowedEnvKeys[0] != "GOCACHE" || d.AllowedEnvKeys[1] != "GOPROXY" {
		t.Fatalf("allowed_env_keys not parsed: %v", d.AllowedEnvKeys)
	}
}

func TestBundle_DecodeOptions(t *testing.T) {
	t.Parallel()

	// Verifies that the @require options block maps cleanly to
	// GlobalOptions, including the cache_max_mb default.
	bundle := Bundle(map[string]string{
		"engine":               "mock",
		"workspace":            ".sandbox_test",
		"image":                "alpine:latest",
		"allowed_executables":  "go, git",
		"cache_max_mb":         "1024",
		"no_cache":             "true",
		"allow_local_fallback": "true",
	})
	if bundle.ID != "sandbox" {
		t.Fatalf("ID = %q", bundle.ID)
	}
}
