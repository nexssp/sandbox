package sandbox

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/nexssp/kernel/xerr"
)

type InProcessEngine struct {
	rootDir string
}

func NewInProcessEngine(rootDir string) *InProcessEngine {
	if rootDir == "" {
		rootDir = filepath.Join(os.TempDir(), "nexss_sandbox")
	}
	if err := os.MkdirAll(rootDir, 0o755); err != nil {
		// Fall back to a per-process temp dir if the requested path is
		// unwritable; the engine still functions with reduced isolation.
		fallback := filepath.Join(os.TempDir(), fmt.Sprintf("nexss_sandbox_%d", os.Getpid()))
		if fallbackErr := os.MkdirAll(fallback, 0o755); fallbackErr != nil {
			slog.Warn("sandbox: workspace dirs unwritable",
				"requested", rootDir, "requested_err", err,
				"fallback", fallback, "fallback_err", fallbackErr)
		}
		rootDir = fallback
	}
	return &InProcessEngine{rootDir: rootDir}
}

func (e *InProcessEngine) Name() string { return "in_process" }

func (e *InProcessEngine) resolveSessionDir(sessionID string) string {
	if sessionID == "" {
		sessionID = "default"
	}
	dir := filepath.Join(e.rootDir, sessionID)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		slog.Warn("sandbox: session dir creation failed", "dir", dir, "err", err)
	}
	return dir
}

func (e *InProcessEngine) Run(ctx context.Context, sessionID string, profile Profile, cmd Command) (ExecutionResult, error) {
	if len(cmd.Argv) == 0 {
		return ExecutionResult{}, xerr.BadRequest("empty command argv")
	}

	workDir := e.resolveSessionDir(sessionID)

	start := time.Now()
	// #nosec G204 -- Executing the supplied argv is this engine's contract; no shell is involved.
	c := exec.CommandContext(ctx, cmd.Argv[0], cmd.Argv[1:]...)
	c.Dir = workDir

	env := os.Environ()
	env = append(env, cmd.Env...)
	if len(profile.AllowedEnvKeys) > 0 {
		env = filterEnv(env, profile.AllowedEnvKeys)
	}
	c.Env = env

	if len(cmd.Stdin) > 0 {
		c.Stdin = bytes.NewReader(cmd.Stdin)
	}

	var stdout, stderr bytes.Buffer
	c.Stdout = &stdout
	c.Stderr = &stderr

	err := c.Run()
	dur := time.Since(start)

	exitCode := 0
	if err != nil {
		exitErr := &exec.ExitError{}
		if errors.As(err, &exitErr) {
			exitCode = exitErr.ExitCode()
		} else {
			return ExecutionResult{}, fmt.Errorf("in-process command %q: %w", cmd.Argv[0], err)
		}
	}

	return ExecutionResult{
		ExitCode: exitCode,
		Stdout:   stdout.String(),
		Stderr:   stderr.String(),
		Duration: dur,
	}, nil
}

func (e *InProcessEngine) WriteFile(_ context.Context, sessionID string, profile Profile, relPath string, content []byte) error {
	profile.ApplyDefaults()
	workspace, err := OpenWorkspaceFS(e.resolveSessionDir(sessionID), profile.MaxFileBytes)
	if err != nil {
		return err
	}
	defer workspace.Close()
	return workspace.WriteFile(relPath, content)
}

func (e *InProcessEngine) ReadFile(_ context.Context, sessionID string, profile Profile, relPath string) ([]byte, error) {
	profile.ApplyDefaults()
	workspace, err := OpenWorkspaceFS(e.resolveSessionDir(sessionID), profile.MaxFileBytes)
	if err != nil {
		return nil, err
	}
	defer workspace.Close()
	return workspace.ReadFile(relPath)
}

func (e *InProcessEngine) Reset(_ context.Context, sessionID string) error {
	return os.RemoveAll(e.resolveSessionDir(sessionID))
}

func (e *InProcessEngine) Close() error { return nil }

func filterEnv(env, allowedKeys []string) []string {
	allowed := make(map[string]struct{}, len(allowedKeys)+4)
	for _, k := range allowedKeys {
		allowed[k] = struct{}{}
	}
	for _, k := range []string{"PATH", "HOME", "USER", "TMPDIR"} {
		allowed[k] = struct{}{}
	}

	out := make([]string, 0, len(env))
	for _, e := range env {
		key, _, ok := strings.Cut(e, "=")
		if !ok {
			out = append(out, e)
			continue
		}
		if _, ok := allowed[key]; ok {
			out = append(out, e)
		}
	}
	return out
}
