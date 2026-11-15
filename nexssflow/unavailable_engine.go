package nexssflow

import (
	"context"
	"fmt"

	"github.com/nexssp/sandbox"
)

// startupErrorEngine preserves a classified engine startup failure for the action boundary,
// where Flow can handle it as an ordinary classified error.
type startupErrorEngine struct {
	name string
	err  error
}

func (e startupErrorEngine) Name() string { return e.name }

func (e startupErrorEngine) Run(context.Context, string, sandbox.Profile, sandbox.Command) (sandbox.ExecutionResult, error) {
	return sandbox.ExecutionResult{}, e.err
}

func (e startupErrorEngine) WriteFile(context.Context, string, sandbox.Profile, string, []byte) error {
	return e.err
}

func (e startupErrorEngine) ReadFile(context.Context, string, sandbox.Profile, string) ([]byte, error) {
	return nil, e.err
}

func (e startupErrorEngine) Reset(context.Context, string) error { return e.err }

func (startupErrorEngine) Close() error { return nil }

func unavailableStartupError(engine string, err error) error {
	var action string
	switch engine {
	case "", "docker":
		action = "start Docker Desktop or the Docker daemon and retry"
	case "podman":
		action = "start the Podman service and retry"
	default:
		action = "check the sandbox engine and retry"
	}
	return fmt.Errorf("sandbox: %s is unavailable; %s: %w", engine, action, err)
}
