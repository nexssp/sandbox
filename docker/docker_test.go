package docker

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/nexssp/sandbox"
)

// TestProfile_FieldsAreHonoured verifies the Profile struct exposes
// every field the Docker engine reads when constructing its `docker
// exec` / `docker update` arguments. This is a compile-time contract:
// if a field is renamed or removed, this test fails to compile.
func TestProfile_FieldsAreHonoured(t *testing.T) {
	t.Parallel()

	p := sandbox.Profile{
		Name:               "builder",
		Image:              "golang:1.26-alpine",
		MemoryMB:           2048,
		CPUs:               2.0,
		PidsLimit:          512,
		NetworkMode:        "none",
		User:               "1000:1000",
		Workspace:          "/workspace",
		ReadOnlyRootFS:     true,
		AllowedExecutables: []string{"go", "git"},
		AllowedEnvKeys:     []string{"GOCACHE", "PATH"},
	}
	p.ApplyDefaults()

	if p.MemoryMB != 2048 {
		t.Fatalf("MemoryMB = %d, want 2048", p.MemoryMB)
	}
	if p.PidsLimit != 512 {
		t.Fatalf("PidsLimit = %d, want 512", p.PidsLimit)
	}
	if p.User != "1000:1000" {
		t.Fatalf("User = %q, want 1000:1000", p.User)
	}
	if p.NetworkMode != "none" {
		t.Fatalf("NetworkMode = %q, want none", p.NetworkMode)
	}
	if !p.ReadOnlyRootFS {
		t.Fatal("ReadOnlyRootFS = false, want true")
	}
}

// TestCacheManager_RecipeKey verifies the cache key is stable across
// calls — same (tool, recipe) pair must always produce the same key.
// A regression here would silently invalidate every cached image.
func TestCacheManager_RecipeKey(t *testing.T) {
	t.Parallel()

	cases := []struct {
		tool   string
		recipe string
	}{
		{"go", "go install"},
		{"go", "go install"}, // dup on purpose
		{"node", "npm ci"},
	}
	keys := make([]string, len(cases))
	for i, c := range cases {
		keys[i] = RecipeKey(c.tool, c.recipe)
	}
	if keys[0] != keys[1] {
		t.Fatalf("RecipeKey not stable: %q vs %q", keys[0], keys[1])
	}
	if keys[0] == keys[2] {
		t.Fatalf("RecipeKey collision between unrelated recipes: %q", keys[0])
	}
}

func TestBoundedBufferCapsOutputAndReportsTruncation(t *testing.T) {
	t.Parallel()

	buffer := newBoundedBuffer(5)
	if n, err := buffer.Write([]byte("1234")); err != nil || n != 4 {
		t.Fatalf("first write = (%d, %v), want (4, nil)", n, err)
	}
	if n, err := buffer.Write([]byte("56789")); err != nil || n != 5 {
		t.Fatalf("second write = (%d, %v), want full input accepted", n, err)
	}
	if got := buffer.String(); got != "12345" {
		t.Fatalf("captured output = %q, want exactly the five-byte limit", got)
	}
	if !buffer.WasTruncated() {
		t.Fatal("WasTruncated() = false, want true")
	}
}

func TestWorkspaceFileOperationsRejectSymlinkEscape(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir()
	secretPath := filepath.Join(outside, "secret.txt")
	if err := os.WriteFile(secretPath, []byte("secret"), 0o600); err != nil {
		t.Fatal(err)
	}
	// Current engine type is SandboxEngine; the NewDockerSandboxEngine
	// constructor remains as a deprecated alias, but tests exercise the
	// current API directly.
	engine := &SandboxEngine{workspaceDir: root}
	root = engine.getSession("").workspaceDir
	if err := os.MkdirAll(root, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(root, "escape")); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	profile := sandbox.Profile{MaxFileBytes: 1024}
	ctx := context.Background()
	if err := engine.WriteFile(ctx, "", profile, "escape/pwned.txt", []byte("no")); err == nil {
		t.Fatal("WriteFile through an external symlink unexpectedly succeeded")
	}
	if _, err := os.Stat(filepath.Join(outside, "pwned.txt")); !os.IsNotExist(err) {
		t.Fatalf("outside file exists or stat failed unexpectedly: %v", err)
	}
	if _, err := engine.ReadFile(ctx, "", profile, "escape/secret.txt"); err == nil {
		t.Fatal("ReadFile through an external symlink unexpectedly succeeded")
	}
}
