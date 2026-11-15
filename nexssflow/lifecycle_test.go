package nexssflow

import (
	"context"
	"testing"
	"time"

	"github.com/nexssp/flow/compiler"
	"github.com/nexssp/flow/runner"
	"github.com/nexssp/kernel/xctx"

	"github.com/nexssp/sandbox"
)

type contextClosingEngine struct {
	gotCtx     context.Context
	closeCalls int
}

func (*contextClosingEngine) Name() string { return "test" }
func (*contextClosingEngine) Run(context.Context, string, sandbox.Profile, sandbox.Command) (sandbox.ExecutionResult, error) {
	return sandbox.ExecutionResult{}, nil
}

func (*contextClosingEngine) WriteFile(context.Context, string, sandbox.Profile, string, []byte) error {
	return nil
}

func (*contextClosingEngine) ReadFile(context.Context, string, sandbox.Profile, string) ([]byte, error) {
	return nil, nil
}
func (*contextClosingEngine) Reset(context.Context, string) error { return nil }
func (e *contextClosingEngine) Close() error {
	e.closeCalls++
	return nil
}

func (e *contextClosingEngine) CloseContext(ctx context.Context) error {
	e.gotCtx = ctx
	return nil
}

func TestBundleRegistersEngineShutdown(t *testing.T) {
	bundle := Bundle(map[string]string{"engine": "mock"})
	if len(bundle.Shutdowns) != 1 {
		t.Fatalf("bundle shutdown callbacks = %d, want 1", len(bundle.Shutdowns))
	}
	if err := bundle.Shutdowns[0](context.Background()); err != nil {
		t.Fatalf("bundle shutdown: %v", err)
	}
}

func TestEngineShutdownUsesHostContextWhenSupported(t *testing.T) {
	engine := &contextClosingEngine{}
	ctx := xctx.WithTenantID(t.Context(), "tenant-from-shutdown")

	if err := engineShutdown(engine)(ctx); err != nil {
		t.Fatalf("engine shutdown: %v", err)
	}
	if engine.gotCtx != ctx {
		t.Fatal("engine shutdown did not receive the host context")
	}
	if got := xctx.TenantIDFrom(engine.gotCtx); got != "tenant-from-shutdown" {
		t.Fatalf("shutdown tenant ID = %q, want preserved request metadata", got)
	}
	if engine.closeCalls != 0 {
		t.Fatalf("Close calls = %d, want 0 when CloseContext is supported", engine.closeCalls)
	}
}

func TestRunnerHostExecutesBundleShutdownAfterInvocation(t *testing.T) {
	engine := &contextClosingEngine{}
	shutdown := engineShutdown(engine)
	host := runner.NewHost(runner.WithShutdownTimeout(time.Second))
	if err := host.Own(compiler.Bundle{ID: "sandbox", Shutdowns: []compiler.ShutdownFunc{shutdown}}); err != nil {
		t.Fatalf("host owns Sandbox bundle: %v", err)
	}
	if err := host.Run(context.Background(), func(context.Context) error { return nil }); err != nil {
		t.Fatalf("host run: %v", err)
	}
	if engine.gotCtx == nil {
		t.Fatal("runner host did not invoke the Sandbox shutdown callback")
	}
	if deadline, ok := engine.gotCtx.Deadline(); !ok || time.Until(deadline) > time.Second {
		t.Fatalf("shutdown context deadline = %v, present = %v; want bounded deadline", deadline, ok)
	}
}
