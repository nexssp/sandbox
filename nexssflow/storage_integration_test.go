package nexssflow_test

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/nexssp/flow/compiler"
	"github.com/nexssp/flow/runner"
	"github.com/nexssp/kernel/xctx"
	"github.com/nexssp/kernel/xerr"
	"github.com/nexssp/storage"
	"github.com/nexssp/storage/memory"
)

func TestSandboxResolvesStorageBlobOnlyWithinAuthenticatedScope(t *testing.T) {
	instance, err := memory.NewBlob().Open(nil)
	if err != nil {
		t.Fatalf("open memory BlobStore: %v", err)
	}
	defer func() {
		if err := instance.Close(); err != nil {
			t.Errorf("close memory BlobStore: %v", err)
		}
	}()

	blobs, err := storage.AssertBlob(instance)
	if err != nil {
		t.Fatalf("assert BlobStore: %v", err)
	}

	ownerCtx := scopedStorageContext("caller-a", "tenant-a")
	payload := "approved report from Storage\n"
	ref, err := blobs.Put(ownerCtx, "documents/report.txt", strings.NewReader(payload))
	if err != nil {
		t.Fatalf("put Storage blob: %v", err)
	}

	resolverBundle := compiler.BundleWithFileResolver(
		compiler.Bundle{ID: "e2e-storage-files"},
		ref.Provider,
		blobs,
	)
	src := fmt.Sprintf(`@require github.com/nexssp/sandbox/nexssflow { engine: "mock", workspace: ".sandbox_e2e_storage_files", enforce_policy: "false" }
@sandbox reader { image: "alpine:latest" }
{ command: "cat", args: ["input.txt"], files: { "input.txt": { Provider: %q, ID: %q, ExpectedSize: %d, ExpectedDigest: %q } } } -> sandbox.reader
`, string(ref.Provider), string(ref.ID), ref.ExpectedSize, string(ref.ExpectedDigest))
	cfg := buildConfig(t, src, resolverBundle)

	result, err := runner.Execute(ownerCtx, cfg, src, "storage_blob_to_sandbox.nflow", nil)
	if err != nil {
		t.Fatalf("execute for owning caller/tenant: %v", err)
	}
	output, ok := result.Output.(map[string]any)
	if !ok {
		t.Fatalf("execution output type = %T, want map[string]any", result.Output)
	}
	if got := output["stdout"]; got != payload {
		t.Fatalf("Sandbox stdout = %#v, want stored payload %q", got, payload)
	}

	for _, scope := range []struct {
		name   string
		caller string
		tenant string
	}{
		{name: "different caller", caller: "caller-b", tenant: "tenant-a"},
		{name: "different tenant", caller: "caller-a", tenant: "tenant-b"},
	} {
		t.Run(scope.name, func(t *testing.T) {
			_, err := runner.Execute(scopedStorageContext(scope.caller, scope.tenant), cfg, src, "storage_blob_denied.nflow", nil)
			if got := xerr.KindFrom(err); got != xerr.KindNotFound {
				t.Fatalf("cross-scope execution kind = %q, want %q (err %v)", got, xerr.KindNotFound, err)
			}
		})
	}
}

func scopedStorageContext(caller, tenant string) context.Context {
	ctx := xctx.WithUserID(context.Background(), caller)
	return xctx.WithTenantID(ctx, tenant)
}
