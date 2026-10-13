package nexssflow

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/nexssp/kernel/xctx"
	"github.com/nexssp/kernel/xerr"
	"github.com/nexssp/kernel/xfile"

	"github.com/nexssp/sandbox"
)

type testFileResolver struct {
	calls int
	ref   xfile.Ref
	info  xfile.Info
	data  []byte
	open  func(context.Context) io.ReadCloser
	err   error
}

func (r *testFileResolver) Open(ctx context.Context, ref xfile.Ref) (io.ReadCloser, xfile.Info, error) {
	r.calls++
	r.ref = ref
	if r.err != nil {
		return nil, xfile.Info{}, r.err
	}
	if r.open != nil {
		return r.open(ctx), r.info, nil
	}
	return io.NopCloser(bytes.NewReader(r.data)), r.info, nil
}

func scopedFileContext() context.Context {
	ctx := xctx.WithUserID(context.Background(), "caller-test")
	return xctx.WithTenantID(ctx, "tenant-test")
}

func fileDigest(data []byte) string {
	sum := sha256.Sum256(data)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func fileRequest(_ []byte, ref BlobRef) map[string]any {
	return map[string]any{
		"command": "cat",
		"args":    []string{"input.txt"},
		"files": map[string]any{
			"input.txt": map[string]any{
				"Provider":       string(ref.Provider),
				"ID":             string(ref.ID),
				"Version":        string(ref.Version),
				"ExpectedSize":   int64(ref.ExpectedSize),
				"ExpectedDigest": string(ref.ExpectedDigest),
			},
		},
	}
}

func TestRunAndMergeWithFileResolverStagesTypedBlobRef(t *testing.T) {
	content := []byte("resolved bytes\n")
	ref := BlobRef{
		Provider:       xfile.Provider("test-store"),
		ID:             xfile.ID("opaque/../../not-a-workspace-path"),
		Version:        xfile.Version("version-7"),
		ExpectedSize:   xfile.ExpectedSize(len(content)),
		ExpectedDigest: xfile.ExpectedDigest(fileDigest(content)),
	}
	resolver := &testFileResolver{
		data: content,
		info: xfile.Info{
			Provider: ref.Provider,
			ID:       ref.ID,
			Version:  ref.Version,
			Size:     int64(len(content)),
			Digest:   fileDigest(content),
		},
	}
	engine := sandbox.NewMockSandbox()
	profile := sandbox.Profile{Name: "test", MaxFileBytes: 1024, MaxWallTime: time.Minute}

	out, err := runAndMergeWithFileResolver(scopedFileContext(), engine, sandbox.PermissivePolicy{}, profile, resolver, fileRequest(content, ref))
	if err != nil {
		t.Fatalf("runAndMergeWithFileResolver: %v", err)
	}
	if resolver.calls != 1 {
		t.Fatalf("resolver calls = %d, want 1", resolver.calls)
	}
	if got := out["stdout"]; got != string(content) {
		t.Fatalf("stdout = %#v, want %q", got, content)
	}
	if got := string(engine.Files["flow_test"]["input.txt"]); got != string(content) {
		t.Fatalf("installed file = %q, want %q", got, content)
	}
	if _, escaped := engine.Files["flow_test"]["opaque/../../not-a-workspace-path"]; escaped {
		t.Fatal("reference ID was incorrectly used as a workspace path")
	}
}

func TestFileRefsRequireExplicitResolverAndAuthenticatedScope(t *testing.T) {
	content := []byte("x")
	ref := BlobRef{Provider: "store", ID: "blob-1"}
	profile := sandbox.Profile{Name: "test", MaxFileBytes: 128, MaxWallTime: time.Minute}
	request := fileRequest(content, ref)

	t.Run("resolver is explicit", func(t *testing.T) {
		engine := sandbox.NewMockSandbox()
		_, err := runAndMerge(context.Background(), engine, sandbox.PermissivePolicy{}, profile, request)
		if got := xerr.KindFrom(err); got != xerr.KindUnavailable {
			t.Fatalf("error kind = %q, want %q (err %v)", got, xerr.KindUnavailable, err)
		}
		if len(engine.Logs) != 0 || len(engine.Files) != 0 {
			t.Fatal("engine was touched without an injected resolver")
		}
	})

	t.Run("scope is required before resolver open", func(t *testing.T) {
		resolver := &testFileResolver{data: content, info: xfile.Info{Provider: ref.Provider, ID: ref.ID, Size: 1, Digest: fileDigest(content)}}
		engine := sandbox.NewMockSandbox()
		_, err := runAndMergeWithFileResolver(context.Background(), engine, sandbox.PermissivePolicy{}, profile, resolver, request)
		if got := xerr.KindFrom(err); got != xerr.KindUnauthorized {
			t.Fatalf("error kind = %q, want %q (err %v)", got, xerr.KindUnauthorized, err)
		}
		if resolver.calls != 0 || len(engine.Files) != 0 {
			t.Fatal("resolver or engine was touched without authenticated caller/tenant scope")
		}
	})
}

func TestFileRefsRejectBadPathsAndIntegrityMetadataBeforeInstall(t *testing.T) {
	content := []byte("verified\n")
	ref := BlobRef{Provider: "store", ID: "blob-1", Version: "v1"}
	profile := sandbox.Profile{Name: "test", MaxFileBytes: 128, MaxWallTime: time.Minute}

	t.Run("destination cannot escape even with permissive policy", func(t *testing.T) {
		resolver := &testFileResolver{data: content, info: xfile.Info{Provider: ref.Provider, ID: ref.ID, Version: ref.Version, Size: int64(len(content)), Digest: fileDigest(content)}}
		engine := sandbox.NewMockSandbox()
		request := map[string]any{
			"command": "cat",
			"files": map[string]any{
				"../escape.txt": map[string]any{"Provider": "store", "ID": "blob-1"},
			},
		}
		_, err := runAndMergeWithFileResolver(scopedFileContext(), engine, sandbox.PermissivePolicy{}, profile, resolver, request)
		if got := xerr.KindFrom(err); got != xerr.KindForbidden {
			t.Fatalf("error kind = %q, want %q (err %v)", got, xerr.KindForbidden, err)
		}
		if resolver.calls != 0 || len(engine.Files) != 0 {
			t.Fatal("invalid destination reached resolver or engine")
		}
	})

	t.Run("version mismatch", func(t *testing.T) {
		resolver := &testFileResolver{data: content, info: xfile.Info{Provider: ref.Provider, ID: ref.ID, Version: "v2", Size: int64(len(content)), Digest: fileDigest(content)}}
		engine := sandbox.NewMockSandbox()
		_, err := runAndMergeWithFileResolver(scopedFileContext(), engine, sandbox.PermissivePolicy{}, profile, resolver, fileRequest(content, ref))
		if got := xerr.KindFrom(err); got != xerr.KindConflict {
			t.Fatalf("error kind = %q, want %q (err %v)", got, xerr.KindConflict, err)
		}
		if len(engine.Files) != 0 {
			t.Fatal("version mismatch installed a file")
		}
	})

	t.Run("expected size mismatch", func(t *testing.T) {
		wrongSizeRef := ref
		wrongSizeRef.ExpectedSize = xfile.ExpectedSize(len(content) + 1)
		resolver := &testFileResolver{data: content, info: xfile.Info{Provider: ref.Provider, ID: ref.ID, Version: ref.Version, Size: int64(len(content)), Digest: fileDigest(content)}}
		engine := sandbox.NewMockSandbox()
		_, err := runAndMergeWithFileResolver(scopedFileContext(), engine, sandbox.PermissivePolicy{}, profile, resolver, fileRequest(content, wrongSizeRef))
		if got := xerr.KindFrom(err); got != xerr.KindConflict {
			t.Fatalf("error kind = %q, want %q (err %v)", got, xerr.KindConflict, err)
		}
		if len(engine.Files) != 0 {
			t.Fatal("expected-size mismatch installed a file")
		}
	})

	t.Run("stream digest mismatch", func(t *testing.T) {
		resolver := &testFileResolver{
			data: []byte("tampered\n"),
			info: xfile.Info{Provider: ref.Provider, ID: ref.ID, Version: ref.Version, Size: int64(len(content)), Digest: fileDigest(content)},
		}
		engine := sandbox.NewMockSandbox()
		_, err := runAndMergeWithFileResolver(scopedFileContext(), engine, sandbox.PermissivePolicy{}, profile, resolver, fileRequest(content, ref))
		if got := xerr.KindFrom(err); got != xerr.KindBadRequest && got != xerr.KindConflict {
			t.Fatalf("error kind = %q, want BadRequest or Conflict (err %v)", got, err)
		}
		if len(engine.Files) != 0 {
			t.Fatal("digest mismatch installed a file")
		}
	})
}

func TestFileRefStageStopsAtMaxFileBytesAndCleansOnCancellation(t *testing.T) {
	profile := sandbox.Profile{Name: "test", MaxFileBytes: 4, MaxWallTime: time.Minute}
	content := []byte("oversize")
	ref := BlobRef{Provider: "store", ID: "blob-1"}

	t.Run("max bytes", func(t *testing.T) {
		resolver := &testFileResolver{data: content, info: xfile.Info{Provider: ref.Provider, ID: ref.ID, Size: int64(len(content)), Digest: fileDigest(content)}}
		engine := sandbox.NewMockSandbox()
		_, err := runAndMergeWithFileResolver(scopedFileContext(), engine, sandbox.PermissivePolicy{}, profile, resolver, fileRequest(content, ref))
		if got := xerr.KindFrom(err); got != xerr.KindBadRequest {
			t.Fatalf("error kind = %q, want %q (err %v)", got, xerr.KindBadRequest, err)
		}
		if len(engine.Files) != 0 {
			t.Fatal("oversized file installed")
		}
	})

	t.Run("cancellation removes partial stage", func(t *testing.T) {
		ctx, cancel := context.WithCancel(scopedFileContext())
		defer cancel()
		cancelContent := []byte("abcd")
		partial := []byte("ab")
		reader := &cancelOnReadCloser{data: partial, cancel: cancel}
		resolver := &testFileResolver{
			info: xfile.Info{Provider: ref.Provider, ID: ref.ID, Size: int64(len(cancelContent)), Digest: fileDigest(cancelContent)},
			open: func(context.Context) io.ReadCloser { return reader },
		}
		engine := sandbox.NewMockSandbox()
		_, err := runAndMergeWithFileResolver(ctx, engine, sandbox.PermissivePolicy{}, profile, resolver, fileRequest(cancelContent, ref))
		if got := xerr.KindFrom(err); got != xerr.KindCanceled {
			t.Fatalf("error kind = %q, want %q (err %v)", got, xerr.KindCanceled, err)
		}
		if len(engine.Files) != 0 {
			t.Fatal("partially staged file was installed after cancellation")
		}
		if !reader.closed.Load() {
			t.Fatal("resolver reader was not closed after cancellation")
		}
	})
}

type cancelOnReadCloser struct {
	data   []byte
	cancel context.CancelFunc
	read   bool
	closed atomic.Bool
}

func (r *cancelOnReadCloser) Read(p []byte) (int, error) {
	if r.read {
		return 0, io.EOF
	}
	r.read = true
	n := copy(p, r.data)
	r.cancel()
	return n, nil
}

func (r *cancelOnReadCloser) Close() error {
	r.closed.Store(true)
	return nil
}

func TestFileRefStageUsesProfileWallTime(t *testing.T) {
	ref := BlobRef{Provider: "store", ID: "slow-file"}
	profile := sandbox.Profile{Name: "test", MaxFileBytes: 4, MaxWallTime: 20 * time.Millisecond}
	reader := &blockingReadCloser{}
	resolver := &testFileResolver{
		info: xfile.Info{Provider: ref.Provider, ID: ref.ID, Size: 0, Digest: fileDigest(nil)},
		open: func(ctx context.Context) io.ReadCloser {
			reader.ctx = ctx
			return reader
		},
	}
	engine := sandbox.NewMockSandbox()
	_, err := runAndMergeWithFileResolver(scopedFileContext(), engine, sandbox.PermissivePolicy{}, profile, resolver, fileRequest(nil, ref))
	if got := xerr.KindFrom(err); got != xerr.KindTimeout {
		t.Fatalf("error kind = %q, want %q (err %v)", got, xerr.KindTimeout, err)
	}
	if len(engine.Files) != 0 {
		t.Fatal("timed-out file was installed")
	}
	if !reader.closed.Load() {
		t.Fatal("resolver reader was not closed after timeout")
	}
}

type blockingReadCloser struct {
	ctx    context.Context
	closed atomic.Bool
}

func (r *blockingReadCloser) Read([]byte) (int, error) {
	<-r.ctx.Done()
	return 0, r.ctx.Err()
}

func (r *blockingReadCloser) Close() error {
	r.closed.Store(true)
	return nil
}

func TestBlobRefDigestValidationRequiresSHA256Prefix(t *testing.T) {
	for _, digest := range []string{"", "sha256:abc", "md5:" + strings.Repeat("0", 32)} {
		if digest == "" {
			continue
		}
		ref := BlobRef{Provider: "store", ID: "id", ExpectedDigest: xfile.ExpectedDigest(digest)}
		if err := validateRef(ref, 100); xerr.KindFrom(err) != xerr.KindBadRequest {
			t.Errorf("validateRef(%q) error = %v, want BadRequest", digest, err)
		}
	}
}
