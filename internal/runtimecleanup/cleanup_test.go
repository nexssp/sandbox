package runtimecleanup

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

const stubEnv = "NEXSS_SANDBOX_CLEANUP_TEST_STUB"

func TestMain(m *testing.M) {
	if os.Getenv(stubEnv) == "1" {
		os.Exit(runRuntimeStub(os.Args[1:]))
	}
	os.Exit(m.Run())
}

func runRuntimeStub(args []string) int {
	if len(args) == 0 {
		return 0
	}
	if logPath := os.Getenv("SANDBOX_CLEANUP_TEST_LOG"); logPath != "" {
		// #nosec G703 -- logPath is supplied by the test's private t.TempDir fixture.
		f, err := os.OpenFile(logPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 2
		}
		if _, err := fmt.Fprintln(f, strings.Join(args, " ")); err != nil {
			_ = f.Close()
			return 2
		}
		if err := f.Close(); err != nil {
			return 2
		}
	}
	switch args[0] {
	case "context":
		if len(args) > 1 && args[1] == "show" {
			fmt.Println("default")
		} else if len(args) > 1 && args[1] == "inspect" {
			fmt.Print(`[{"Endpoints":{"docker":{"Host":"unix:///var/run/docker.sock"}}}]`)
		}
	case "system":
		fmt.Print("[]")
	case "ps":
		fmt.Print(os.Getenv("SANDBOX_CLEANUP_TEST_IDS"))
	case "inspect":
		if len(args) < 2 {
			return 2
		}
		id := args[len(args)-1]
		if !validContainerID(id) {
			return 2
		}
		path := filepath.Join(os.Getenv("SANDBOX_CLEANUP_TEST_FIXTURES"), id+".json")
		// #nosec G703 -- fixtureDir is test-owned and id is validated as a container ID above.
		data, err := os.ReadFile(path)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 3
		}
		fmt.Print(string(data))
	case "rm":
		return 0
	}
	return 0
}

func installRuntimeStub(t *testing.T) (logPath, fixtureDir string) {
	t.Helper()
	binDir := t.TempDir()
	logPath = filepath.Join(t.TempDir(), "runtime.log")
	fixtureDir = t.TempDir()
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	binary, err := os.ReadFile(executable)
	if err != nil {
		t.Fatal(err)
	}
	for _, runtimeName := range []string{"docker", "podman"} {
		stubName := runtimeName
		if runtime.GOOS == "windows" {
			stubName += ".exe"
		}
		stubPath := filepath.Join(binDir, stubName)
		// #nosec G703 -- stubPath is under this test's private t.TempDir and stubName is fixed.
		if err := os.WriteFile(stubPath, binary, 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(stubPath, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("PATH", binDir+string(os.PathListSeparator)+os.Getenv("PATH"))
	t.Setenv(stubEnv, "1")
	t.Setenv("DOCKER_HOST", "")
	t.Setenv("DOCKER_CONTEXT", "")
	t.Setenv("CONTAINER_HOST", "")
	t.Setenv("CONTAINER_CONNECTION", "")
	t.Setenv("SANDBOX_CLEANUP_TEST_LOG", logPath)
	t.Setenv("SANDBOX_CLEANUP_TEST_FIXTURES", fixtureDir)
	return logPath, fixtureDir
}

func TestLeaseIsExclusiveUntilClosed(t *testing.T) {
	key := "lease-test-" + t.Name()
	first, err := Acquire(key)
	if err != nil {
		t.Fatalf("Acquire: %v", err)
	}
	defer first.Close()

	if _, acquired, err := TryAcquire(key); err != nil || acquired {
		t.Fatalf("TryAcquire while held = (%v, %v), want (false, nil)", acquired, err)
	}
	if err := first.Close(); err != nil {
		t.Fatalf("Close lease: %v", err)
	}
	second, acquired, err := TryAcquire(key)
	if err != nil || !acquired {
		t.Fatalf("TryAcquire after close = (%v, %v), want (true, nil)", acquired, err)
	}
	if err := second.Close(); err != nil {
		t.Fatalf("Close second lease: %v", err)
	}
}

func TestPruneStaleRemovesOnlyOldUnlockedContainersForSameWorkspace(t *testing.T) {
	logPath, fixtureDir := installRuntimeStub(t)
	workspace := t.TempDir()
	marker := filepath.Join(workspace, "preserve.txt")
	if err := os.WriteFile(marker, []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}

	staleID := strings.Repeat("a", 64)
	activeID := strings.Repeat("b", 64)
	recentID := strings.Repeat("c", 64)
	otherWorkspaceID := strings.Repeat("d", 64)
	foreignOwnerID := strings.Repeat("e", 64)
	badInspectID := strings.Repeat("f", 64)
	legacyID := strings.Repeat("1", 64)
	ids := []string{staleID, activeID, recentID, otherWorkspaceID, foreignOwnerID, badInspectID, legacyID}
	t.Setenv("SANDBOX_CLEANUP_TEST_IDS", strings.Join(ids, "\n"))

	staleLabels, err := Labels(workspace, "lease-stale")
	if err != nil {
		t.Fatal(err)
	}
	activeLabels, err := Labels(workspace, "lease-active")
	if err != nil {
		t.Fatal(err)
	}
	recentLabels, err := Labels(workspace, "lease-recent")
	if err != nil {
		t.Fatal(err)
	}
	otherWorkspaceLabels, err := Labels(filepath.Join(workspace, "other"), "lease-other-workspace")
	if err != nil {
		t.Fatal(err)
	}
	foreignOwnerLabels, err := Labels(workspace, "lease-other-owner")
	if err != nil {
		t.Fatal(err)
	}
	foreignOwnerLabels[labelHost] = "another-host"

	writeInspection(t, fixtureDir, staleID, staleLabels, time.Now().Add(-48*time.Hour))
	writeInspection(t, fixtureDir, activeID, activeLabels, time.Now().Add(-48*time.Hour))
	writeInspection(t, fixtureDir, recentID, recentLabels, time.Now().Add(-12*time.Hour))
	writeInspection(t, fixtureDir, otherWorkspaceID, otherWorkspaceLabels, time.Now().Add(-48*time.Hour))
	writeInspection(t, fixtureDir, foreignOwnerID, foreignOwnerLabels, time.Now().Add(-48*time.Hour))
	writeInspection(t, fixtureDir, legacyID, map[string]string{}, time.Now().Add(-48*time.Hour))
	if err := os.WriteFile(filepath.Join(fixtureDir, badInspectID+".json"), []byte("not-json"), 0o600); err != nil {
		t.Fatal(err)
	}

	activeLease, err := Acquire("lease-active")
	if err != nil {
		t.Fatal(err)
	}
	defer activeLease.Close()

	if err := PruneStale(context.Background(), "docker", workspace, 24*time.Hour); err != nil {
		t.Fatalf("PruneStale: %v", err)
	}
	logData, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatal(err)
	}
	log := string(logData)
	if !strings.Contains(log, "rm -f "+staleID) {
		t.Fatalf("owned stale container was not removed: %s", log)
	}
	for _, protected := range []string{activeID, recentID, otherWorkspaceID, foreignOwnerID, badInspectID, legacyID} {
		if strings.Contains(log, "rm -f "+protected) {
			t.Errorf("protected container %q was removed: %s", protected, log)
		}
	}
	if got, err := os.ReadFile(marker); err != nil || string(got) != "keep" {
		t.Fatalf("workspace marker = %q, error = %v; want preserved data", got, err)
	}
}

func writeInspection(t *testing.T, dir, id string, labels map[string]string, created time.Time) {
	t.Helper()
	value := map[string]any{
		"Id":      id,
		"Created": created.Format(time.RFC3339Nano),
		"Config":  map[string]any{"Labels": labels},
	}
	data, err := json.Marshal([]any{value})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, id+".json"), data, 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestCleanupRejectsInvalidRuntimeName(t *testing.T) {
	if err := PruneStale(context.Background(), "sh", t.TempDir(), time.Hour); err == nil {
		t.Fatal("PruneStale accepted an unsupported runtime")
	}
}

func TestLocalEndpointDetection(t *testing.T) {
	for endpoint, wantLocal := range map[string]bool{
		"unix:///var/run/docker.sock":                      true,
		"unix://remote.example/var/run/docker.sock":        false,
		"npipe:////./pipe/docker_engine":                   true,
		"npipe:////remote-host/pipe/docker_engine":         false,
		"tcp://127.0.0.1:2375":                             false,
		"tcp://[::1]:2375":                                 false,
		"http://localhost:2375":                            false,
		"https://127.0.0.1:2376":                           false,
		"tcp://docker.internal:2375":                       false,
		"ssh://user@remote.example/run/podman/podman.sock": false,
	} {
		if got := isLocalEndpoint(endpoint); got != wantLocal {
			t.Errorf("isLocalEndpoint(%q) = %v, want %v", endpoint, got, wantLocal)
		}
	}
}

func TestPruneStaleSkipsRemoteDaemonEndpoints(t *testing.T) {
	t.Run("docker", func(t *testing.T) {
		logPath, _ := installRuntimeStub(t)
		t.Setenv("DOCKER_HOST", "tcp://remote.example:2376")
		if err := PruneStale(context.Background(), "docker", t.TempDir(), time.Hour); err != nil {
			t.Fatalf("PruneStale: %v", err)
		}
		if _, err := os.Stat(logPath); !os.IsNotExist(err) {
			t.Fatalf("remote Docker runtime was contacted; stat err = %v", err)
		}
	})
	t.Run("podman", func(t *testing.T) {
		logPath, _ := installRuntimeStub(t)
		t.Setenv("CONTAINER_HOST", "ssh://user@remote.example/run/podman/podman.sock")
		if err := PruneStale(context.Background(), "podman", t.TempDir(), time.Hour); err != nil {
			t.Fatalf("PruneStale: %v", err)
		}
		if _, err := os.Stat(logPath); !os.IsNotExist(err) {
			t.Fatalf("remote Podman runtime was contacted; stat err = %v", err)
		}
	})
}

func TestPruneStaleSkipsUnknownPodmanConnection(t *testing.T) {
	logPath, _ := installRuntimeStub(t)
	t.Setenv("CONTAINER_CONNECTION", "missing-connection")
	if err := PruneStale(context.Background(), "podman", t.TempDir(), time.Hour); err != nil {
		t.Fatalf("PruneStale: %v", err)
	}
	logData, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(logData), "ps -aq") {
		t.Fatalf("unknown Podman connection was treated as local: %s", logData)
	}
}
