package podman

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/nexssp/sandbox"
)

// TestProfile_FieldsAreHonoured verifies the Profile struct exposes
// every field the Podman engine reads when constructing its `podman
// exec` / `podman update` arguments. Mirror of the Docker test.
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

func TestWorkspaceFileOperationsRejectSymlinkEscape(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir()
	secretPath := filepath.Join(outside, "secret.txt")
	if err := os.WriteFile(secretPath, []byte("secret"), 0o600); err != nil {
		t.Fatal(err)
	}
	// Current engine type is SandboxEngine; the NewPodmanSandboxEngine
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
