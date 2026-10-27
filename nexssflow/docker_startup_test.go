package nexssflow_test

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/nexssp/flow/runner"
)

func TestDockerUnavailableIsRecoverableBeforeCommandRuns(t *testing.T) {
	// Keep the Docker probe deterministic even on machines with Docker installed.
	t.Setenv("PATH", t.TempDir())

	workspace := t.TempDir()
	marker := filepath.Join(t.TempDir(), "command-ran")
	src := fmt.Sprintf(`@require github.com/nexssp/sandbox/nexssflow { engine: "docker", workspace: %q, enforce_policy: "false" }
{ command: "touch", args: [%q] } -> sandbox.exec
? on_error {
xerr.KindUnavailable -> runtime.const @{ value: { recovered: true } },
  else -> error.reraise
}
`, workspace, marker)

	cfg := buildConfig(t, src)
	ex, err := runner.Execute(context.Background(), cfg, src, "docker_unavailable.nflow", map[string]any{})
	if err != nil {
		t.Fatalf("execute should recover from Docker unavailability: %v", err)
	}

	out, ok := ex.Output.(map[string]any)
	if !ok {
		t.Fatalf("output type = %T, want map[string]any", ex.Output)
	}
	if recovered, _ := out["recovered"].(bool); !recovered {
		t.Fatalf("recovered = %v, want true; output: %#v", out["recovered"], out)
	}
	if _, err := os.Stat(marker); !os.IsNotExist(err) {
		t.Fatalf("sandbox command ran despite unavailable Docker (stat err: %v)", err)
	}
}
