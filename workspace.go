package sandbox

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path"

	"github.com/nexssp/kernel/xerr"
	"github.com/nexssp/kernel/xfs"
)

type WorkspaceFS struct {
	root     *os.Root
	maxBytes int64
}

func OpenWorkspaceFS(directory string, maxBytes int) (*WorkspaceFS, error) {
	if maxBytes <= 0 {
		return nil, xerr.BadRequest("sandbox: workspace file limit must be positive")
	}

	if err := os.MkdirAll(directory, 0o755); err != nil {
		return nil, xerr.Internal(fmt.Sprintf("sandbox: create workspace root %q: %v", directory, err))
	}

	root, err := os.OpenRoot(directory)
	if err != nil {
		return nil, xerr.Internal(fmt.Sprintf("sandbox: open workspace root %q: %v", directory, err))
	}

	return &WorkspaceFS{root: root, maxBytes: int64(maxBytes)}, nil
}

// WriteFile atomically replaces a confined workspace file. A failed write
// leaves an existing destination untouched and removes the temporary file.
func (w *WorkspaceFS) WriteFile(relativePath string, content []byte) (resultErr error) {
	if w == nil || w.root == nil {
		return xerr.Internal("sandbox: workspace filesystem is closed")
	}

	if int64(len(content)) > w.maxBytes {
		return xerr.BadRequest(fmt.Sprintf("sandbox: file is %d bytes; limit is %d", len(content), w.maxBytes))
	}

	clean, err := xfs.Rel(relativePath)
	if err != nil {
		return err
	}

	parent := path.Dir(clean)
	if mkErr := w.root.MkdirAll(parent, 0o700); mkErr != nil {
		return xerr.Internal("sandbox: create workspace directory", mkErr)
	}

	tempPath, err := workspaceTempName(clean)
	if err != nil {
		return xerr.Internal("sandbox: generate workspace temporary file name", err)
	}
	file, openErr := w.root.OpenFile(tempPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if openErr != nil {
		return xerr.Internal("sandbox: create workspace temporary file", openErr)
	}
	installed := false
	fileClosed := false
	defer func() {
		if !installed {
			if !fileClosed {
				if closeErr := file.Close(); closeErr != nil {
					resultErr = errors.Join(resultErr, xerr.Internal("sandbox: close incomplete workspace file", closeErr))
				}
			}
			if removeErr := w.root.Remove(tempPath); removeErr != nil && !errors.Is(removeErr, os.ErrNotExist) {
				resultErr = errors.Join(resultErr, xerr.Internal("sandbox: remove incomplete workspace file", removeErr))
			}
		}
	}()

	written, writeErr := file.Write(content)
	if writeErr != nil {
		return xerr.Internal("sandbox: write workspace temporary file", writeErr)
	}
	if written != len(content) {
		return xerr.Internal("sandbox: write workspace temporary file", io.ErrShortWrite)
	}
	if syncErr := file.Sync(); syncErr != nil {
		return xerr.Internal("sandbox: sync workspace temporary file", syncErr)
	}
	if closeErr := file.Close(); closeErr != nil {
		fileClosed = true
		return xerr.Internal("sandbox: close workspace temporary file", closeErr)
	}
	fileClosed = true
	if renameErr := w.root.Rename(tempPath, clean); renameErr != nil {
		return xerr.Internal("sandbox: atomically install workspace file", renameErr)
	}
	installed = true
	return nil
}

func workspaceTempName(clean string) (string, error) {
	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return "", err
	}
	return path.Join(path.Dir(clean), "."+path.Base(clean)+"."+hex.EncodeToString(nonce[:])+".tmp"), nil
}

func (w *WorkspaceFS) ReadFile(relativePath string) ([]byte, error) {
	if w == nil || w.root == nil {
		return nil, xerr.Internal("sandbox: workspace filesystem is closed")
	}

	clean, err := xfs.Rel(relativePath)
	if err != nil {
		return nil, err
	}

	file, openErr := w.root.Open(clean)
	if openErr != nil {
		if os.IsNotExist(openErr) {
			return nil, xerr.NotFound(fmt.Sprintf("sandbox: file %q not found", relativePath), openErr)
		}

		return nil, xerr.Internal("sandbox: open workspace file", openErr)
	}
	defer file.Close()

	data, readErr := io.ReadAll(io.LimitReader(file, w.maxBytes+1))
	if readErr != nil {
		return nil, xerr.Internal("sandbox: read workspace file", readErr)
	}

	if int64(len(data)) > w.maxBytes {
		return nil, xerr.BadRequest(fmt.Sprintf("sandbox: file %q exceeds limit %d", relativePath, w.maxBytes))
	}

	return data, nil
}

func (w *WorkspaceFS) Close() error {
	if w == nil || w.root == nil {
		return nil
	}

	err := w.root.Close()
	w.root = nil

	return err
}
