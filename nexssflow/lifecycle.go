package nexssflow

import (
	"context"

	"github.com/nexssp/flow/compiler"

	"github.com/nexssp/sandbox"
)

type contextEngineCloser interface {
	CloseContext(context.Context) error
}

func engineShutdown(engine sandbox.Engine) compiler.ShutdownFunc {
	return func(ctx context.Context) error {
		if closer, ok := engine.(contextEngineCloser); ok {
			return closer.CloseContext(ctx)
		}
		return engine.Close()
	}
}
