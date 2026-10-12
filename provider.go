package sandbox

import (
	"context"
	"io"
)

// Provider is an OPTIONAL extension of Engine implemented by engines
// that can also expose filesystem introspection and long-lived
// background processes. None of the bundled engines (Docker, Podman,
// InProcess, Mock) implement it today; the interface is kept here so
// downstream consumers (e.g. A2A workers) can declare their engine as
// "Provider-capable" without changing the Engine contract.
//
// Callers that need Provider methods should use a type assertion:
//
//	if p, ok := engine.(sandbox.Provider); ok {
//	    info, err := p.Stat(ctx, sessionID, path)
//	}
//
// The bundled engines all expose Stat/ListDir/SpawnBackground via
// their own engine-specific APIs (see docker.DockerSandboxEngine for
// an example); this interface is reserved for the cross-engine
// abstraction that may be added in a future release.
type Provider interface {
	Engine

	// FileSystem operations
	Stat(ctx context.Context, sessionID, path string) (FileInfo, error)
	ListDir(ctx context.Context, sessionID, path string) ([]FileInfo, error)
	OpenStream(ctx context.Context, sessionID, path string) (io.ReadCloser, error)

	// Process lifecycle
	SpawnBackground(ctx context.Context, sessionID string, cmd Command) (ProcessHandle, error)
}

// FileInfo describes a single file or directory inside a sandbox
// workspace. Sizes are in bytes; ModTime is a Unix timestamp.
type FileInfo struct {
	Name    string `json:"name"`
	Size    int64  `json:"size"`
	IsDir   bool   `json:"is_dir"`
	ModTime int64  `json:"mod_time"`
}

// ProcessHandle represents a background process spawned via
// SpawnBackground. PID is the OS-level process ID (or container PID
// namespace PID, depending on engine); Kill terminates the process;
// Wait blocks until the process exits and returns its result.
type ProcessHandle interface {
	PID() int
	Kill(ctx context.Context) error
	Wait(ctx context.Context) (ExecutionResult, error)
}
