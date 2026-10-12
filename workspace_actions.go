package sandbox

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/nexssp/kernel/action"
	"github.com/nexssp/kernel/xerr"
	"github.com/nexssp/kernel/xfs"
)

type ReadReq struct {
	Path string `json:"path" validate:"required"`
}

type WriteReq struct {
	Path    string `json:"path" validate:"required"`
	Content string `json:"content" validate:"required"`
}

type EditReq struct {
	Path    string `json:"path" validate:"required"`
	OldText string `json:"old_text" validate:"required"`
	NewText string `json:"new_text" validate:"required"`
}

// WorkspaceSuite manages hermetic filesystem actions and implements action.ActionProvider.
type WorkspaceSuite struct {
	fs *WorkspaceFS
}

var _ action.ActionProvider = (*WorkspaceSuite)(nil)

// NewWorkspaceSuite initializes an escape-proof filesystem workspace using os.Root (Go 1.24+).
func NewWorkspaceSuite(workDir string, maxFileBytes int) (*WorkspaceSuite, error) {
	if maxFileBytes <= 0 {
		maxFileBytes = 5 << 20 // 5 MB default
	}

	fs, err := OpenWorkspaceFS(workDir, maxFileBytes)
	if err != nil {
		return nil, err
	}

	return &WorkspaceSuite{fs: fs}, nil
}

// NewConfinedWorkspaceTools provides backwards compatibility with tests and tooling suites.
func NewConfinedWorkspaceTools(workDir string, maxFileBytes int) (*WorkspaceSuite, error) {
	return NewWorkspaceSuite(workDir, maxFileBytes)
}

// Close terminates the workspace filesystem handle.
func (s *WorkspaceSuite) Close() error {
	if s == nil || s.fs == nil {
		return nil
	}

	return s.fs.Close()
}

// Actions returns all workspace operations as standard Kernel actions.
func (s *WorkspaceSuite) Actions() []action.AnyAction {
	return []action.AnyAction{
		s.ReadAction(),
		s.WriteAction(),
		s.EditAction(),
	}
}

// ReadAction reads text from a file inside the isolated workspace.
func (s *WorkspaceSuite) ReadAction() *action.BuiltAction[ReadReq, string] {
	return action.New("workspace.read_file", func(_ context.Context, req ReadReq) (string, error) {
		clean, err := xfs.Rel(req.Path)
		if err != nil {
			return "", err
		}

		data, err := s.fs.ReadFile(clean)
		if err != nil {
			return "", err
		}

		return string(data), nil
	}).
		Description("Reads text from a file inside the isolated workspace").
		Timeout(5 * time.Second).
		Build()
}

// WriteAction writes text to a file inside the isolated workspace.
func (s *WorkspaceSuite) WriteAction() *action.BuiltAction[WriteReq, string] {
	return action.New("workspace.write_file", func(_ context.Context, req WriteReq) (string, error) {
		clean, err := xfs.Rel(req.Path)
		if err != nil {
			return "", err
		}

		if err := s.fs.WriteFile(clean, []byte(req.Content)); err != nil {
			return "", err
		}

		return fmt.Sprintf("Wrote %d bytes to %s", len(req.Content), clean), nil
	}).
		Description("Writes text to a file inside the isolated workspace").
		Timeout(5 * time.Second).
		Build()
}

// EditAction safely replaces targeted text inside an existing workspace file.
func (s *WorkspaceSuite) EditAction() *action.BuiltAction[EditReq, string] {
	return action.New("workspace.edit_file", func(_ context.Context, req EditReq) (string, error) {
		clean, err := xfs.Rel(req.Path)
		if err != nil {
			return "", err
		}

		data, err := s.fs.ReadFile(clean)
		if err != nil {
			return "", err
		}

		content := string(data)
		if !strings.Contains(content, req.OldText) {
			return "", xerr.BadRequest(fmt.Sprintf("workspace: old_text pattern not found in %q", req.Path))
		}

		newContent := strings.Replace(content, req.OldText, req.NewText, 1)
		if err := s.fs.WriteFile(clean, []byte(newContent)); err != nil {
			return "", xerr.Internal(fmt.Sprintf("workspace: failed writing edit to %q", req.Path), err)
		}

		return "Successfully edited " + clean, nil
	}).
		Description("Replaces matching text in a workspace file").
		Timeout(5 * time.Second).
		Build()
}
