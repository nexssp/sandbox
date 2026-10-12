package sandbox_test

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/nexssp/sandbox"
)

func TestWorkspaceFS_ConfinedOperations(t *testing.T) {
	t.Parallel()

	tempDir := t.TempDir()
	ws, err := sandbox.OpenWorkspaceFS(tempDir, 1<<20)
	if err != nil {
		t.Fatalf("OpenWorkspaceFS failed: %v", err)
	}
	defer ws.Close()

	// 1. Write file
	err = ws.WriteFile("src/main.go", []byte("package main"))
	if err != nil {
		t.Fatalf("WriteFile failed: %v", err)
	}

	// 2. Read file
	data, err := ws.ReadFile("src/main.go")
	if err != nil || string(data) != "package main" {
		t.Fatalf("ReadFile mismatch: got %q err %v", string(data), err)
	}

	// 3. Escape prevention
	err = ws.WriteFile("../escape.txt", []byte("bad"))
	if err == nil {
		t.Fatal("expected escape path to fail")
	}
}

func TestMockSandbox_Lifecycle(t *testing.T) {
	t.Parallel()

	sb := sandbox.NewMockSandbox()
	profile := sandbox.Profile{Name: "test-profile"}

	ctx := context.Background()

	_ = sb.WriteFile(ctx, "session-42", profile, "test.txt", []byte("hello world"))

	res, err := sb.Run(ctx, "session-42", profile, sandbox.Command{Argv: []string{"cat", "test.txt"}})
	if err != nil || res.Stdout != "hello world" {
		t.Fatalf("unexpected cat output: %q err=%v", res.Stdout, err)
	}
}

func TestInProcessFileOperationsRejectSymlinkEscape(t *testing.T) {
	root := t.TempDir()
	sessionDir := filepath.Join(root, "safe-session")
	outside := t.TempDir()
	if err := os.MkdirAll(sessionDir, 0o700); err != nil {
		t.Fatal(err)
	}
	secretPath := filepath.Join(outside, "secret.txt")
	if err := os.WriteFile(secretPath, []byte("secret"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(sessionDir, "escape")); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}

	engine := sandbox.NewInProcessEngine(root)
	profile := sandbox.Profile{MaxFileBytes: 1024}
	ctx := context.Background()
	if err := engine.WriteFile(ctx, "safe-session", profile, "escape/pwned.txt", []byte("no")); err == nil {
		t.Fatal("WriteFile through an external symlink unexpectedly succeeded")
	}
	if _, err := os.Stat(filepath.Join(outside, "pwned.txt")); !os.IsNotExist(err) {
		t.Fatalf("outside file exists or stat failed unexpectedly: %v", err)
	}
	if _, err := engine.ReadFile(ctx, "safe-session", profile, "escape/secret.txt"); err == nil {
		t.Fatal("ReadFile through an external symlink unexpectedly succeeded")
	}
}

func TestInProcessRunReturnsCommandStartupError(t *testing.T) {
	engine := sandbox.NewInProcessEngine(t.TempDir())

	_, err := engine.Run(context.Background(), "startup-error", sandbox.Profile{}, sandbox.Command{
		Argv: []string{"nexss-sandbox-command-that-does-not-exist"},
	})
	if err == nil || !strings.Contains(err.Error(), "nexss-sandbox-command-that-does-not-exist") {
		t.Fatalf("Run error = %v, want a descriptive command startup error", err)
	}
}
