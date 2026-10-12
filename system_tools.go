package sandbox

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/nexssp/kernel/action"
	"github.com/nexssp/kernel/xerr"
)

type ReadFileReq struct {
	Path   string `json:"path" validate:"required"`
	Offset int64  `json:"offset,omitempty"`
	Limit  int64  `json:"limit,omitempty"`
}

type WriteFileReq struct {
	Path    string `json:"path" validate:"required"`
	Content string `json:"content" validate:"required"`
}

type PatchFileReq struct {
	Path   string `json:"path" validate:"required"`
	Search string `json:"search" validate:"required"`
	Target string `json:"target" validate:"required"`
}

type ExecReq struct {
	Command string   `json:"command" validate:"required"`
	Args    []string `json:"args,omitempty"`
	Timeout int      `json:"timeout_seconds,omitempty"`
}

type ExecRes struct {
	ExitCode int    `json:"exit_code"`
	Stdout   string `json:"stdout"`
	Stderr   string `json:"stderr"`
	Duration string `json:"duration"`
}

func BuildSystemToolSuite(sb Engine, sessionID string, profile Profile) []action.AnyAction {
	readAction := action.New("fs.read", func(ctx context.Context, req ReadFileReq) (string, error) {
		data, err := sb.ReadFile(ctx, sessionID, profile, req.Path)
		if err != nil {
			return "", err
		}

		if req.Offset > 0 && req.Offset < int64(len(data)) {
			data = data[req.Offset:]
		}

		if req.Limit > 0 && int64(len(data)) > req.Limit {
			data = data[:req.Limit]
		}

		return string(data), nil
	}).
		Description("Reads file contents from isolated workspace").
		Build()

	writeAction := action.New("fs.write", func(ctx context.Context, req WriteFileReq) (string, error) {
		if err := sb.WriteFile(ctx, sessionID, profile, req.Path, []byte(req.Content)); err != nil {
			return "", err
		}

		return fmt.Sprintf("Wrote %d bytes to %s", len(req.Content), req.Path), nil
	}).
		Description("Writes text file to isolated workspace").
		Build()

	patchAction := action.New("fs.patch", func(ctx context.Context, req PatchFileReq) (string, error) {
		data, err := sb.ReadFile(ctx, sessionID, profile, req.Path)
		if err != nil {
			return "", err
		}

		content := string(data)
		if !strings.Contains(content, req.Search) {
			return "", xerr.BadRequest(fmt.Sprintf("pattern %q not found in %s", req.Search, req.Path))
		}

		updated := strings.Replace(content, req.Search, req.Target, 1)
		if err := sb.WriteFile(ctx, sessionID, profile, req.Path, []byte(updated)); err != nil {
			return "", err
		}

		return "Successfully patched " + req.Path, nil
	}).
		Description("Replaces matching substring inside workspace file").
		Build()

	execAction := action.New("sandbox.exec", func(ctx context.Context, req ExecReq) (ExecRes, error) {
		timeout := 30 * time.Second
		if req.Timeout > 0 {
			timeout = time.Duration(req.Timeout) * time.Second
		}

		execCtx, cancel := context.WithTimeout(ctx, timeout)
		defer cancel()

		cmd := Command{
			Argv: append([]string{req.Command}, req.Args...),
		}
		start := time.Now()

		res, err := sb.Run(execCtx, sessionID, profile, cmd)
		if err != nil {
			return ExecRes{}, err
		}

		return ExecRes{
			ExitCode: res.ExitCode,
			Stdout:   res.Stdout,
			Stderr:   res.Stderr,
			Duration: time.Since(start).String(),
		}, nil
	}).
		Description("Runs sandboxed process with argv parameters").
		Build()

	return []action.AnyAction{readAction, writeAction, patchAction, execAction}
}
