package sandbox

import (
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

func (w *WorkspaceFS) WriteFile(relativePath string, content []byte) error {
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

	if mkErr := w.root.MkdirAll(path.Dir(clean), 0o700); mkErr != nil {
		return xerr.Internal("sandbox: create workspace directory", mkErr)
	}

	file, openErr := w.root.OpenFile(clean, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if openErr != nil {
		return xerr.Internal("sandbox: open workspace file", openErr)
	}

	_, writeErr := file.Write(content)
	closeErr := file.Close()

	if writeErr != nil {
		return xerr.Internal("sandbox: write workspace file", writeErr)
	}

	if closeErr != nil {
		return xerr.Internal("sandbox: close workspace file", closeErr)
	}

	return nil
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
