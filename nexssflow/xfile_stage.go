package nexssflow

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"

	"github.com/nexssp/kernel/xerr"
	"github.com/nexssp/kernel/xfile"
	"github.com/nexssp/kernel/xfs"

	"github.com/nexssp/sandbox"
)

const fileStageBufferBytes = 32 << 10

type stagedFile struct {
	target string
	name   string
	size   int64
}

type stagedFiles struct {
	root     *os.Root
	dir      string
	files    []stagedFile
	maxBytes int64
}

// stageFileRefs validates and resolves every reference before any engine write.
// Temporary paths are generated locally and are never derived from a Ref.
func stageFileRefs(
	ctx context.Context,
	resolver xfile.Resolver,
	policy sandbox.Policy,
	profile sandbox.Profile,
	refs map[string]BlobRef,
) (*stagedFiles, error) {
	if len(refs) == 0 {
		return &stagedFiles{}, nil
	}
	if resolver == nil {
		return nil, xerr.Unavailable("sandbox: file references require an explicitly injected xfile resolver")
	}
	if ctx == nil {
		return nil, xerr.BadRequest("sandbox: file staging context is required")
	}
	if err := contextStageError(ctx); err != nil {
		return nil, err
	}
	if _, err := xfile.ScopeFromContext(ctx); err != nil {
		return nil, err
	}

	maxBytes := int64(profile.MaxFileBytes)
	targets, err := fileStageTargets(policy, profile, refs, maxBytes)
	if err != nil {
		return nil, err
	}
	batch, err := newStagedFiles(maxBytes)
	if err != nil {
		return nil, err
	}
	keep := false
	defer func() {
		if !keep {
			batch.Close()
		}
	}()

	for index, target := range targets {
		staged, err := stageFileRef(ctx, resolver, policy, profile, refs[target], target, index, batch.root, maxBytes)
		if err != nil {
			return nil, err
		}
		batch.files = append(batch.files, staged)
	}

	keep = true
	return batch, nil
}

func fileStageTargets(policy sandbox.Policy, profile sandbox.Profile, refs map[string]BlobRef, maxBytes int64) ([]string, error) {
	if profile.MaxFileBytes <= 0 {
		return nil, xerr.BadRequest("sandbox: MaxFileBytes must be positive")
	}
	targets := make([]string, 0, len(refs))
	for target := range refs {
		targets = append(targets, target)
	}
	sort.Strings(targets)
	for _, target := range targets {
		if err := policy.ValidateWrite(profile, target, 0); err != nil {
			return nil, err
		}
		if _, err := xfs.Rel(target); err != nil {
			return nil, xerr.Forbidden(fmt.Sprintf("sandbox: invalid file destination %q", target), err)
		}
		if err := validateRef(refs[target], maxBytes); err != nil {
			return nil, fmt.Errorf("sandbox: invalid file reference for %q: %w", target, err)
		}
	}
	return targets, nil
}

func newStagedFiles(maxBytes int64) (*stagedFiles, error) {
	dir, err := os.MkdirTemp("", "sandbox-xfile-stage-")
	if err != nil {
		return nil, xerr.Internal("sandbox: create confined file staging directory", err)
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		if removeErr := os.RemoveAll(dir); removeErr != nil {
			return nil, errors.Join(
				xerr.Internal("sandbox: open confined file staging directory", err),
				xerr.Internal("sandbox: remove unusable file staging directory", removeErr),
			)
		}
		return nil, xerr.Internal("sandbox: open confined file staging directory", err)
	}
	return &stagedFiles{root: root, dir: dir, maxBytes: maxBytes}, nil
}

func stageFileRef(
	ctx context.Context,
	resolver xfile.Resolver,
	policy sandbox.Policy,
	profile sandbox.Profile,
	ref BlobRef,
	target string,
	index int,
	root *os.Root,
	maxBytes int64,
) (stagedFile, error) {
	if err := contextStageError(ctx); err != nil {
		return stagedFile{}, err
	}
	reader, info, err := openResolvedFile(ctx, resolver, ref, target, maxBytes)
	if err != nil {
		return stagedFile{}, err
	}
	stopClose := context.AfterFunc(ctx, func() { _ = reader.Close() })
	name := fmt.Sprintf("file-%06d", index)
	actualSize, actualDigest, streamErr := stageReader(ctx, root, name, reader, maxBytes)
	closeErr := reader.Close()
	stopClose()
	if streamErr != nil {
		return stagedFile{}, fmt.Errorf("sandbox: stage referenced file %q: %w", target, streamErr)
	}
	if closeErr != nil {
		return stagedFile{}, xerr.Internal(fmt.Sprintf("sandbox: close resolved file reader for %q", target), closeErr)
	}
	if err := validateStagedFile(policy, profile, ref, target, info, actualSize, actualDigest); err != nil {
		return stagedFile{}, err
	}
	return stagedFile{target: target, name: name, size: actualSize}, nil
}

func openResolvedFile(ctx context.Context, resolver xfile.Resolver, ref BlobRef, target string, maxBytes int64) (io.ReadCloser, xfile.Info, error) {
	reader, info, openErr := resolver.Open(ctx, ref)
	if openErr != nil {
		if reader != nil {
			if closeErr := reader.Close(); closeErr != nil {
				openErr = errors.Join(openErr, xerr.Internal("sandbox: close reader after resolver failure", closeErr))
			}
		}
		if ctxErr := contextStageError(ctx); ctxErr != nil {
			return nil, xfile.Info{}, ctxErr
		}
		return nil, xfile.Info{}, fmt.Errorf("sandbox: resolve file reference for %q: %w", target, openErr)
	}
	if reader == nil {
		return nil, xfile.Info{}, xerr.Internal(fmt.Sprintf("sandbox: resolver returned no reader for %q", target))
	}
	if err := validateInfo(ref, info, maxBytes); err != nil {
		if closeErr := reader.Close(); closeErr != nil {
			err = errors.Join(err, xerr.Internal("sandbox: close reader after metadata validation failure", closeErr))
		}
		return nil, xfile.Info{}, fmt.Errorf("sandbox: invalid resolved file metadata for %q: %w", target, err)
	}
	return reader, info, nil
}

func validateStagedFile(
	policy sandbox.Policy,
	profile sandbox.Profile,
	ref BlobRef,
	target string,
	info xfile.Info,
	actualSize int64,
	actualDigest string,
) error {
	if actualSize != info.Size {
		return xerr.Conflict(fmt.Sprintf("sandbox: resolved file size changed while reading %q", target))
	}
	if !equalDigest(actualDigest, info.Digest) {
		return xerr.Conflict(fmt.Sprintf("sandbox: resolved file digest mismatch for %q", target))
	}
	if ref.ExpectedSize != 0 && actualSize != int64(ref.ExpectedSize) {
		return xerr.Conflict(fmt.Sprintf("sandbox: expected size mismatch for %q", target))
	}
	if ref.ExpectedDigest != "" && !equalDigest(actualDigest, string(ref.ExpectedDigest)) {
		return xerr.Conflict(fmt.Sprintf("sandbox: expected digest mismatch for %q", target))
	}
	return policy.ValidateWrite(profile, target, int(actualSize))
}

func validateRef(ref BlobRef, maxBytes int64) error {
	if ref.Provider == "" {
		return xerr.BadRequest("file reference provider is required")
	}
	if ref.ID == "" {
		return xerr.BadRequest("file reference ID is required")
	}
	if ref.ExpectedSize < 0 {
		return xerr.BadRequest("file reference expected size cannot be negative")
	}
	if int64(ref.ExpectedSize) > maxBytes {
		return xerr.BadRequest(fmt.Sprintf("file reference expected size exceeds MaxFileBytes (%d)", maxBytes))
	}
	if ref.ExpectedDigest != "" && !validSHA256Digest(string(ref.ExpectedDigest)) {
		return xerr.BadRequest("file reference expected digest must use sha256:<hex>")
	}
	return nil
}

func validateInfo(ref BlobRef, info xfile.Info, maxBytes int64) error {
	if info.Provider != ref.Provider || info.ID != ref.ID {
		return xerr.Conflict("resolver opened a different provider object than requested")
	}
	if ref.Version != "" && info.Version != ref.Version {
		return xerr.Conflict("resolved file version does not match the expected version")
	}
	if info.Size < 0 {
		return xerr.Internal("resolver returned a negative file size")
	}
	if info.Size > maxBytes {
		return xerr.BadRequest(fmt.Sprintf("resolved file size %d exceeds MaxFileBytes %d", info.Size, maxBytes))
	}
	if ref.ExpectedSize != 0 && info.Size != int64(ref.ExpectedSize) {
		return xerr.Conflict("resolved file size does not match the expected size")
	}
	if !validSHA256Digest(info.Digest) {
		return xerr.Internal("resolver returned a digest that is not sha256:<hex>")
	}
	if ref.ExpectedDigest != "" && !equalDigest(string(ref.ExpectedDigest), info.Digest) {
		return xerr.Conflict("resolved file digest does not match the expected digest")
	}
	return nil
}

func validSHA256Digest(digest string) bool {
	algorithm, value, ok := strings.Cut(digest, ":")
	if !ok || algorithm != "sha256" || len(value) != sha256.Size*2 {
		return false
	}
	decoded, err := hex.DecodeString(value)
	return err == nil && len(decoded) == sha256.Size
}

func equalDigest(left, right string) bool {
	return strings.EqualFold(left, right)
}

func stageReader(ctx context.Context, root *os.Root, name string, src io.Reader, maxBytes int64) (size int64, digest string, resultErr error) {
	file, err := root.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return 0, "", xerr.Internal("sandbox: create confined file staging file", err)
	}
	committed := false
	fileClosed := false
	defer func() {
		if !committed {
			if !fileClosed {
				if closeErr := file.Close(); closeErr != nil {
					resultErr = errors.Join(resultErr, xerr.Internal("sandbox: close incomplete staging file", closeErr))
				}
			}
			if removeErr := root.Remove(name); removeErr != nil && !errors.Is(removeErr, os.ErrNotExist) {
				resultErr = errors.Join(resultErr, xerr.Internal("sandbox: remove incomplete staging file", removeErr))
			}
		}
	}()

	total, digest, copyErr := copyResolvedFile(ctx, file, src, maxBytes)
	if copyErr != nil {
		return 0, "", copyErr
	}
	if err := file.Sync(); err != nil {
		return 0, "", xerr.Internal("sandbox: sync confined file staging file", err)
	}
	if err := file.Close(); err != nil {
		fileClosed = true
		return 0, "", xerr.Internal("sandbox: close confined file staging file", err)
	}
	fileClosed = true
	committed = true
	return total, digest, nil
}

func copyResolvedFile(ctx context.Context, dst io.Writer, src io.Reader, maxBytes int64) (size int64, digest string, resultErr error) {
	hasher := sha256.New()
	buf := make([]byte, fileStageBufferBytes)
	var total int64
	zeroReads := 0
	for {
		if err := contextStageError(ctx); err != nil {
			return 0, "", err
		}
		n, readErr := src.Read(buf)
		if n > 0 {
			zeroReads = 0
			if int64(n) > maxBytes-total {
				return 0, "", xerr.BadRequest(fmt.Sprintf("resolved file exceeds MaxFileBytes %d", maxBytes))
			}
			if err := writeAll(dst, buf[:n]); err != nil {
				return 0, "", xerr.Internal("sandbox: write confined file staging file", err)
			}
			if _, err := hasher.Write(buf[:n]); err != nil {
				return 0, "", xerr.Internal("sandbox: hash resolved file", err)
			}
			total += int64(n)
		} else if readErr == nil {
			zeroReads++
			if zeroReads >= 100 {
				return 0, "", xerr.Internal("sandbox: read resolved file", io.ErrNoProgress)
			}
		}

		if readErr != nil {
			if errors.Is(readErr, io.EOF) {
				break
			}
			if ctxErr := contextStageError(ctx); ctxErr != nil {
				return 0, "", ctxErr
			}
			return 0, "", xerr.Internal("sandbox: read resolved file", readErr)
		}
	}

	if err := contextStageError(ctx); err != nil {
		return 0, "", err
	}
	return total, "sha256:" + hex.EncodeToString(hasher.Sum(nil)), nil
}

func writeAll(dst io.Writer, content []byte) error {
	for len(content) > 0 {
		n, err := dst.Write(content)
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrShortWrite
		}
		content = content[n:]
	}
	return nil
}

func contextStageError(ctx context.Context) error {
	if ctx == nil {
		return nil
	}
	err := ctx.Err()
	if err == nil {
		return nil
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return xerr.Timeout("sandbox: file staging deadline exceeded", err)
	}
	return xerr.Canceled("sandbox: file staging canceled", err)
}

func (s *stagedFiles) install(ctx context.Context, engine sandbox.Engine, sessionID string, profile sandbox.Profile) error {
	if err := contextStageError(ctx); err != nil {
		return err
	}
	for _, staged := range s.files {
		if err := contextStageError(ctx); err != nil {
			return err
		}
		file, err := s.root.Open(staged.name)
		if err != nil {
			return xerr.Internal(fmt.Sprintf("sandbox: reopen staged file %q", staged.target), err)
		}
		content, readErr := io.ReadAll(io.LimitReader(file, s.maxBytes+1))
		closeErr := file.Close()
		if readErr != nil {
			return xerr.Internal(fmt.Sprintf("sandbox: read staged file %q", staged.target), readErr)
		}
		if closeErr != nil {
			return xerr.Internal(fmt.Sprintf("sandbox: close staged file %q", staged.target), closeErr)
		}
		if int64(len(content)) != staged.size || int64(len(content)) > s.maxBytes {
			return xerr.Internal(fmt.Sprintf("sandbox: staged file %q changed before installation", staged.target))
		}
		if err := engine.WriteFile(ctx, sessionID, profile, staged.target, content); err != nil {
			if ctxErr := contextStageError(ctx); ctxErr != nil {
				return ctxErr
			}
			return fmt.Errorf("sandbox: install staged file %q: %w", staged.target, err)
		}
	}
	return nil
}

func (s *stagedFiles) Close() {
	if s == nil {
		return
	}
	if s.root != nil {
		_ = s.root.Close()
		s.root = nil
	}
	if s.dir != "" {
		_ = os.RemoveAll(s.dir)
		s.dir = ""
	}
}
