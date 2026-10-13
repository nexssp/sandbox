package nexssflow

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/nexssp/sandbox"
)

type noIOEngine struct {
	calls       int
	deadline    time.Time
	hasDeadline bool
	result      sandbox.ExecutionResult
}

func (e *noIOEngine) Name() string { return "no-io" }

func (e *noIOEngine) Run(ctx context.Context, _ string, _ sandbox.Profile, _ sandbox.Command) (sandbox.ExecutionResult, error) {
	e.calls++
	e.deadline, e.hasDeadline = ctx.Deadline()
	return e.result, nil
}

func (e *noIOEngine) WriteFile(context.Context, string, sandbox.Profile, string, []byte) error {
	e.calls++
	return nil
}

func (e *noIOEngine) ReadFile(context.Context, string, sandbox.Profile, string) ([]byte, error) {
	e.calls++
	return nil, nil
}

func (e *noIOEngine) Reset(context.Context, string) error {
	e.calls++
	return nil
}

func (e *noIOEngine) Close() error { return nil }

func strictTestProfile() sandbox.Profile {
	profile := sandbox.Profile{
		Name:               "strict",
		Image:              "alpine:latest",
		MemoryMB:           512,
		CPUs:               1,
		PidsLimit:          64,
		NetworkMode:        "none",
		ReadOnlyRootFS:     true,
		AllowedExecutables: []string{"go"},
		MaxWallTime:        time.Minute,
		MaxOutputBytes:     1 << 20,
		MaxFileBytes:       1 << 20,
	}
	profile.ApplyDefaults()
	return profile
}

func TestRunAndMergeEnforcesProfileWallTimeAndReportsTruncation(t *testing.T) {
	t.Parallel()

	engine := &noIOEngine{result: sandbox.ExecutionResult{ExitCode: 0, Truncated: true}}
	profile := strictTestProfile()
	profile.MaxWallTime = 200 * time.Millisecond
	out, err := runAndMerge(context.Background(), engine, sandbox.StaticPolicy{}, profile, map[string]any{
		"command":         "go",
		"timeout_seconds": 30,
	})
	if err != nil {
		t.Fatalf("runAndMerge: %v", err)
	}
	if !engine.hasDeadline {
		t.Fatal("engine context has no deadline")
	}
	remaining := time.Until(engine.deadline)
	if remaining <= 0 || remaining > profile.MaxWallTime {
		t.Fatalf("remaining deadline = %v, want positive and <= profile cap %v", remaining, profile.MaxWallTime)
	}
	if out["truncated"] != true {
		t.Fatalf("truncated = %#v, want true", out["truncated"])
	}
}

func TestRunAndMergePolicyPreflightPrecedesEngineIO(t *testing.T) {
	t.Parallel()

	t.Run("invalid profile", func(t *testing.T) {
		t.Parallel()
		engine := &noIOEngine{}
		profile := strictTestProfile()
		profile.Image = ""

		_, err := runAndMerge(context.Background(), engine, sandbox.StaticPolicy{}, profile, map[string]any{
			"command": "go",
		})
		if err == nil || !strings.Contains(err.Error(), "image is required") {
			t.Fatalf("error = %v, want invalid-profile error", err)
		}
		if engine.calls != 0 {
			t.Fatalf("engine calls = %d, want 0", engine.calls)
		}
	})

	t.Run("disallowed command", func(t *testing.T) {
		t.Parallel()
		engine := &noIOEngine{}

		_, err := runAndMerge(context.Background(), engine, sandbox.StaticPolicy{}, strictTestProfile(), map[string]any{
			"command": "rm",
			"files": map[string]any{
				"hello.txt": map[string]any{"Provider": "test", "ID": "blob"},
			},
		})
		if err == nil || !strings.Contains(err.Error(), "not on the profile allowlist") {
			t.Fatalf("error = %v, want command-allowlist error", err)
		}
		if engine.calls != 0 {
			t.Fatalf("engine calls = %d, want 0", engine.calls)
		}
	})

	t.Run("invalid later file", func(t *testing.T) {
		t.Parallel()
		engine := &noIOEngine{}

		_, err := runAndMergeWithFileResolver(scopedFileContext(), engine, sandbox.StaticPolicy{}, strictTestProfile(), &testFileResolver{}, map[string]any{
			"command": "go",
			"files": map[string]any{
				"valid.txt": map[string]any{"Provider": "test", "ID": "good"},
				"../escape": map[string]any{"Provider": "test", "ID": "bad"},
			},
		})
		if err == nil || !strings.Contains(err.Error(), "escapes the workspace") {
			t.Fatalf("error = %v, want invalid-write-path error", err)
		}
		if engine.calls != 0 {
			t.Fatalf("engine calls = %d, want 0", engine.calls)
		}
	})
}
