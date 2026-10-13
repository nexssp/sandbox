package nexssflow

import (
	"testing"

	"github.com/nexssp/kernel/xfile"
)

func TestBundleWithFileResolverBindsResolverToExecAction(t *testing.T) {
	content := []byte("resolver reached bundle\n")
	ref := BlobRef{Provider: xfile.Provider("test-store"), ID: xfile.ID("embed-1")}
	resolver := &testFileResolver{
		data: content,
		info: xfile.Info{Provider: ref.Provider, ID: ref.ID, Size: int64(len(content)), Digest: fileDigest(content)},
	}
	bundle := BundleWithFileResolver(map[string]string{
		"engine":         "mock",
		"enforce_policy": "false",
	}, resolver)
	if len(bundle.Libraries) != 1 {
		t.Fatalf("bundle library count = %d, want 1", len(bundle.Libraries))
	}
	if len(bundle.Libraries[0].Actions) != 1 {
		t.Fatalf("bundle action count = %d, want 1", len(bundle.Libraries[0].Actions))
	}

	request := fileRequest(content, ref)
	got, err := bundle.Libraries[0].Actions[0].DoAny(scopedFileContext(), request)
	if err != nil {
		t.Fatalf("exec action: %v", err)
	}
	result, ok := got.(map[string]any)
	if !ok {
		t.Fatalf("action output type = %T, want map[string]any", got)
	}
	if result["stdout"] != string(content) {
		t.Fatalf("stdout = %#v, want %q", result["stdout"], content)
	}
	if resolver.calls != 1 {
		t.Fatalf("resolver calls = %d, want 1", resolver.calls)
	}
}
