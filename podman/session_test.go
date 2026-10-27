package podman

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/nexssp/sandbox"
)

const podmanStubEnv = "NEXSS_SANDBOX_TEST_PODMAN_STUB"

func TestMain(m *testing.M) {
	if os.Getenv(podmanStubEnv) == "1" {
		os.Exit(runPodmanStub(os.Args[1:]))
	}
	os.Exit(m.Run())
}

func runPodmanStub(args []string) int {
	if logPath := os.Getenv("SANDBOX_RUNTIME_LOG"); logPath != "" {
		log, err := os.OpenFile(logPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600) // #nosec G703 -- Test log path is assigned from t.TempDir by installPodmanStub.
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 2
		}
		if _, err := fmt.Fprintln(log, strings.Join(args, " ")); err != nil {
			fmt.Fprintln(os.Stderr, err)
			_ = log.Close()
			return 2
		}
		if err := log.Close(); err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 2
		}
	}

	if len(args) == 0 {
		return 0
	}
	switch args[0] {
	case "version":
		if os.Getenv("SANDBOX_FAIL_VERSION") == "1" {
			return 42
		}
	case "ps":
		for _, arg := range args[1:] {
			if name, ok := strings.CutPrefix(arg, "name="); ok {
				fmt.Println(name)
			}
		}
	case "update":
		if os.Getenv("SANDBOX_FAIL_UPDATE") == "1" {
			fmt.Fprintln(os.Stderr, "resource-update-failed")
			return 42
		}
	case "exec":
		fmt.Println("executed")
	}
	return 0
}

func installPodmanStub(t *testing.T) string {
	t.Helper()
	binDir := t.TempDir()
	logPath := filepath.Join(t.TempDir(), "podman.log")
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	binary, err := os.ReadFile(executable)
	if err != nil {
		t.Fatal(err)
	}
	stubName := "podman"
	if runtime.GOOS == "windows" {
		stubName += ".exe"
	}
	if err := os.WriteFile(filepath.Join(binDir, stubName), binary, 0o700); err != nil { // #nosec G306,G703 -- Test runtime stub is a copy of the test binary under t.TempDir.
		t.Fatal(err)
	}
	t.Setenv("PATH", binDir+string(os.PathListSeparator)+os.Getenv("PATH"))
	t.Setenv(podmanStubEnv, "1")
	t.Setenv("SANDBOX_RUNTIME_LOG", logPath)
	return logPath
}

func TestSessionWorkspacesAndResetAreIsolated(t *testing.T) {
	logPath := installPodmanStub(t)
	ctx := context.Background()
	workspaceRoot := t.TempDir()
	engine, err := NewSandboxEngine(Config{
		WorkspaceDir:       workspaceRoot,
		DefaultImage:       "test-image",
		AllowLocalFallback: true,
	})
	if err != nil {
		t.Fatalf("NewSandboxEngine() error = %v", err)
	}
	defer func() {
		if err := engine.Close(); err != nil {
			t.Errorf("Close() error = %v", err)
		}
	}()

	profile := sandbox.Profile{MaxFileBytes: 1024}
	if err := engine.WriteFile(ctx, "alpha", profile, "marker.txt", []byte("alpha")); err != nil {
		t.Fatal(err)
	}
	if err := engine.WriteFile(ctx, "beta", profile, "marker.txt", []byte("beta")); err != nil {
		t.Fatal(err)
	}

	alpha := engine.getSession("alpha")
	beta := engine.getSession("beta")
	if alpha.workspaceDir == beta.workspaceDir || alpha.containerName == beta.containerName {
		t.Fatalf("sessions share isolation state: alpha=%+v beta=%+v", alpha, beta)
	}
	if _, err := engine.ReadFile(ctx, "alpha", profile, "marker.txt"); err != nil {
		t.Fatalf("alpha could not read its file: %v", err)
	}
	if got, err := engine.ReadFile(ctx, "beta", profile, "marker.txt"); err != nil || string(got) != "beta" {
		t.Fatalf("beta file = %q, error = %v; want beta", got, err)
	}

	if _, err := engine.Run(ctx, "alpha", sandbox.Profile{}, sandbox.Command{Argv: []string{"true"}}); err != nil {
		t.Fatalf("Run(alpha) error = %v", err)
	}
	if _, err := engine.Run(ctx, "beta", sandbox.Profile{}, sandbox.Command{Argv: []string{"true"}}); err != nil {
		t.Fatalf("Run(beta) error = %v", err)
	}
	if err := engine.Reset(ctx, "alpha"); err != nil {
		t.Fatalf("Reset(alpha) error = %v", err)
	}
	if _, err := engine.ReadFile(ctx, "alpha", profile, "marker.txt"); err == nil {
		t.Fatal("alpha workspace remained after reset")
	}
	if got, err := engine.ReadFile(ctx, "beta", profile, "marker.txt"); err != nil || string(got) != "beta" {
		t.Fatalf("beta file after alpha reset = %q, error = %v; want beta", got, err)
	}

	log, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(log), "exec -i") || !strings.Contains(string(log), alpha.containerName) {
		t.Fatalf("runtime log does not show alpha container execution: %s", log)
	}
	if !strings.Contains(string(log), "rm -f "+alpha.containerName) {
		t.Fatalf("runtime log does not show alpha-only container reset: %s", log)
	}
	if strings.Contains(string(log), "rm -f "+beta.containerName) {
		t.Fatalf("reset of alpha removed beta's container: %s", log)
	}
}

func TestAllowLocalFallbackDoesNotRunHostCommand(t *testing.T) {
	installPodmanStub(t)
	t.Setenv("SANDBOX_FAIL_VERSION", "1")
	_, err := NewSandboxEngine(Config{WorkspaceDir: t.TempDir(), AllowLocalFallback: true})
	if err == nil {
		t.Fatal("NewSandboxEngine() succeeded despite unavailable Podman while fallback was enabled")
	}
}

func TestRunReturnsResourceUpdateFailure(t *testing.T) {
	logPath := installPodmanStub(t)
	t.Setenv("SANDBOX_FAIL_UPDATE", "1")
	engine := &SandboxEngine{workspaceDir: t.TempDir(), defaultImage: "test-image", containerName: "engine-test"}
	_, err := engine.Run(context.Background(), "session", sandbox.Profile{}, sandbox.Command{Argv: []string{"true"}})
	if err == nil || !strings.Contains(err.Error(), "resource-update-failed") {
		t.Fatalf("Run() error = %v, want resource update failure", err)
	}
	log, readErr := os.ReadFile(logPath)
	if readErr != nil {
		t.Fatal(readErr)
	}
	if strings.Contains(string(log), "exec ") {
		t.Fatalf("command executed despite failed resource update: %s", log)
	}
}

func TestDefaultSessionUsesBaseWorkspace(t *testing.T) {
	workspaceRoot := t.TempDir()
	engine := &SandboxEngine{workspaceDir: workspaceRoot, containerName: "engine-test"}

	if got := engine.getSession("").workspaceDir; got != workspaceRoot {
		t.Fatalf("default session workspace = %q, want base workspace %q", got, workspaceRoot)
	}
}

func TestCloseRemovesAllSessionContainersAndPreservesWorkspaces(t *testing.T) {
	logPath := installPodmanStub(t)
	engine := &SandboxEngine{workspaceDir: t.TempDir(), containerName: "engine-test"}
	sessions := []*sandboxSession{engine.getSession(""), engine.getSession("alpha"), engine.getSession("beta")}
	for _, session := range sessions {
		session.containerCreated = true
		if err := os.MkdirAll(session.workspaceDir, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(session.workspaceDir, "marker.txt"), []byte(session.containerName), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	if err := engine.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	log, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatal(err)
	}
	for _, session := range sessions {
		if !strings.Contains(string(log), "rm -f "+session.containerName) {
			t.Errorf("Close() did not remove container %q: %s", session.containerName, log)
		}
		got, err := os.ReadFile(filepath.Join(session.workspaceDir, "marker.txt"))
		if err != nil || string(got) != session.containerName {
			t.Errorf("Close() did not preserve workspace file for %q: contents=%q, error=%v", session.containerName, got, err)
		}
	}
}
