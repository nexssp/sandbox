package sandbox_test

import (
	"context"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/nexssp/kernel/xerr"

	"github.com/nexssp/sandbox"
)

func TestWorkspaceFS_PathTraversalAttacks(t *testing.T) {
	t.Parallel()

	tempDir := t.TempDir()
	outsideFile := filepath.Join(tempDir, "sensitive_root.txt")
	_ = os.WriteFile(outsideFile, []byte("SUPER_SECRET_KEY=12345"), 0o600)

	wsDir := filepath.Join(tempDir, "workspace")
	_ = os.MkdirAll(wsDir, 0o755)

	ws, err := sandbox.NewConfinedWorkspaceTools(wsDir, 1<<20)
	if err != nil {
		t.Fatalf("failed initializing workspace: %v", err)
	}
	t.Cleanup(func() {
		if err := ws.Close(); err != nil {
			t.Errorf("close workspace fs: %v", err)
		}
	})

	readAct := ws.ReadAction()
	writeAct := ws.WriteAction()
	ctx := context.Background()

	attacks := []struct {
		name string
		path string
	}{
		{"Relative dot-dot", "../sensitive_root.txt"},
		{"Deep traversal", "../../../../../../../etc/passwd"},
		{"Absolute path unix", "/etc/shadow"},
		{"Null byte injection", "valid.txt\x00../../sensitive_root.txt"},
		{"Double slash traversal", "..//..//sensitive_root.txt"},
		{"Windows separator traversal", "..\\sensitive_root.txt"},
	}

	for _, tc := range attacks {
		t.Run("Read-"+tc.name, func(t *testing.T) {
			t.Parallel()
			_, err := readAct.Do(ctx, sandbox.ReadReq{Path: tc.path})
			if err == nil {
				t.Fatalf("SECURITY FLAW: Path traversal succeeded for %q", tc.path)
			}
			if xerr.KindFrom(err) != xerr.KindForbidden && xerr.KindFrom(err) != xerr.KindBadRequest && xerr.KindFrom(err) != xerr.KindNotFound {
				t.Fatalf("expected Forbidden/BadRequest error, got kind %q: %v", xerr.KindFrom(err), err)
			}
		})

		t.Run("Write-"+tc.name, func(t *testing.T) {
			_, err := writeAct.Do(ctx, sandbox.WriteReq{Path: tc.path, Content: "malicious payload"})
			if err == nil {
				t.Fatalf("SECURITY FLAW: Write traversal succeeded for %q", tc.path)
			}
		})
	}
}

func TestWorkspaceFS_HighConcurrencyRace(t *testing.T) {
	t.Parallel()

	wsDir := t.TempDir()
	ws, err := sandbox.NewConfinedWorkspaceTools(wsDir, 1<<20)
	if err != nil {
		t.Fatalf("failed init: %v", err)
	}
	defer ws.Close()

	writeAct := ws.WriteAction()
	readAct := ws.ReadAction()
	ctx := context.Background()

	const routines = 64
	var wg sync.WaitGroup
	wg.Add(routines)

	for i := range routines {
		go func(_ int) {
			defer wg.Done()
			fileName := filepath.Join("sub", "worker.txt")
			_, _ = writeAct.Do(ctx, sandbox.WriteReq{Path: fileName, Content: "content"})
			_, _ = readAct.Do(ctx, sandbox.ReadReq{Path: fileName})
		}(i)
	}

	wg.Wait()
}
