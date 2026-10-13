package sandbox

import (
	"os"
	"path/filepath"
	"testing"
)

func TestWorkspaceFSWriteFileAtomicallyReplacesSymlink(t *testing.T) {
	t.Parallel()
	workspaceDir := t.TempDir()
	outsideDir := t.TempDir()
	outsidePath := filepath.Join(outsideDir, "outside.txt")
	if err := os.WriteFile(outsidePath, []byte("outside secret"), 0o600); err != nil {
		t.Fatalf("write outside file: %v", err)
	}
	if err := os.Symlink(outsidePath, filepath.Join(workspaceDir, "input.txt")); err != nil {
		t.Fatalf("create workspace symlink: %v", err)
	}

	workspace, err := OpenWorkspaceFS(workspaceDir, 1024)
	if err != nil {
		t.Fatalf("OpenWorkspaceFS: %v", err)
	}
	defer workspace.Close()
	if err := workspace.WriteFile("input.txt", []byte("verified replacement")); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	outside, err := os.ReadFile(outsidePath)
	if err != nil {
		t.Fatalf("read outside file: %v", err)
	}
	if string(outside) != "outside secret" {
		t.Fatalf("outside file changed to %q", outside)
	}
	installed, err := workspace.ReadFile("input.txt")
	if err != nil {
		t.Fatalf("ReadFile installed file: %v", err)
	}
	if string(installed) != "verified replacement" {
		t.Fatalf("installed file = %q, want replacement", installed)
	}
	info, err := os.Lstat(filepath.Join(workspaceDir, "input.txt"))
	if err != nil {
		t.Fatalf("Lstat installed file: %v", err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		t.Fatal("installed path is still a symlink")
	}
}
