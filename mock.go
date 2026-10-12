package sandbox

import (
	"context"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/nexssp/kernel/xerr"
	"github.com/nexssp/kernel/xfs"
)

type MockSandboxEngine struct {
	mu            sync.RWMutex
	Files         map[string]map[string][]byte
	Profiles      map[string]Profile
	Logs          []Command
	workspacesDir string
}

func NewMockSandbox() *MockSandboxEngine {
	wsDir := "workspaces"
	if err := os.MkdirAll(wsDir, 0o755); err != nil {
		// Non-fatal: callers that rely on the on-disk workspace will see
		// the failure through their own os calls.
		_ = err
	}

	return &MockSandboxEngine{
		Files:         make(map[string]map[string][]byte),
		Profiles:      make(map[string]Profile),
		workspacesDir: wsDir,
	}
}

func (m *MockSandboxEngine) Name() string { return "mock-sandbox" }

func (m *MockSandboxEngine) Run(_ context.Context, sessionID string, profile Profile, command Command) (ExecutionResult, error) {
	profile.ApplyDefaults()
	m.mu.Lock()
	defer m.mu.Unlock()

	m.Profiles[sessionID] = profile
	m.Logs = append(m.Logs, command)

	if len(command.Argv) == 0 {
		return ExecutionResult{ExitCode: 1, Stderr: "empty command"}, nil
	}

	if m.Files[sessionID] == nil {
		m.Files[sessionID] = make(map[string][]byte)
	}

	var stdout, stderr string

	exe := command.Argv[0]
	switch exe {
	case "ls":
		var names []string
		for f := range m.Files[sessionID] {
			names = append(names, f)
		}

		stdout = strings.Join(names, "\n") + "\n"
	case "cat":
		if len(command.Argv) >= 2 {
			filename := command.Argv[1]
			if data, ok := m.Files[sessionID][filename]; ok {
				stdout = string(data)
			} else {
				stderr = fmt.Sprintf("cat: %s: No such file or directory\n", filename)

				return ExecutionResult{ExitCode: 1, Stderr: stderr}, nil
			}
		}
	case "gofmt":
		stdout = "Formatted code.\n"
	case "go":
		stdout = "PASS\nok  \tsandbox/test\t0.015s\n"
	default:
		stdout = fmt.Sprintf("Executed: %v\n", command.Argv)
	}

	return ExecutionResult{
		ExitCode: 0,
		Stdout:   stdout,
		Stderr:   stderr,
		Duration: 10 * time.Millisecond,
	}, nil
}

func (m *MockSandboxEngine) WriteFile(_ context.Context, sessionID string, _ Profile, relativePath string, content []byte) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	clean, err := xfs.Rel(relativePath)
	if err != nil {
		return err
	}

	if m.Files[sessionID] == nil {
		m.Files[sessionID] = make(map[string][]byte)
	}

	m.Files[sessionID][clean] = append([]byte(nil), content...)

	return nil
}

func (m *MockSandboxEngine) ReadFile(_ context.Context, sessionID string, _ Profile, relativePath string) ([]byte, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	clean, err := xfs.Rel(relativePath)
	if err != nil {
		return nil, err
	}

	if files := m.Files[sessionID]; files != nil {
		if data, ok := files[clean]; ok {
			return append([]byte(nil), data...), nil
		}
	}

	return nil, xerr.NotFound(fmt.Sprintf("sandbox: file %q not found", relativePath))
}

func (m *MockSandboxEngine) Reset(_ context.Context, sessionID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	delete(m.Files, sessionID)
	delete(m.Profiles, sessionID)

	return nil
}

func (m *MockSandboxEngine) Close() error { return nil }
