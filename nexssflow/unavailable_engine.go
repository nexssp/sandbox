package nexssflow

import (
	"context"
	"fmt"

	"github.com/nexssp/sandbox"
)

// unavailableEngine preserves an engine startup failure for the action boundary,
// where Flow can handle it as an ordinary classified error.
type unavailableEngine struct {
	name string
	err  error
}

func (e unavailableEngine) Name() string { return e.name }

func (e unavailableEngine) Run(context.Context, string, sandbox.Profile, sandbox.Command) (sandbox.ExecutionResult, error) {
	return sandbox.ExecutionResult{}, e.err
}

func (e unavailableEngine) WriteFile(context.Context, string, sandbox.Profile, string, []byte) error {
	return e.err
}

func (e unavailableEngine) ReadFile(context.Context, string, sandbox.Profile, string) ([]byte, error) {
	return nil, e.err
}

func (e unavailableEngine) Reset(context.Context, string) error { return e.err }

func (unavailableEngine) Close() error { return nil }

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
