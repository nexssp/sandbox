package podman

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/nexssp/kernel/xerr"

	"github.com/nexssp/sandbox"
)

const podmanProbeTimeout = 5 * time.Second

type ExecRecord struct {
	Command   string        `json:"command"`
	Args      []string      `json:"args"`
	ExitCode  int           `json:"exit_code"`
	Stdout    string        `json:"stdout"`
	Stderr    string        `json:"stderr"`
	Duration  time.Duration `json:"duration"`
	Image     string        `json:"image"`
	Container string        `json:"container"`
	Started   bool          `json:"started"`
	Stream    string        `json:"stream,omitempty"`
	Line      string        `json:"line,omitempty"`
}

type Config struct {
	WorkspaceDir       string
	DefaultImage       string
	AllowLocalFallback bool
	EventHandler       func(ExecRecord)
}

// SandboxEngine is the podman-backed implementation of sandbox.Engine.
type SandboxEngine struct {
	mu            sync.RWMutex
	workspaceDir  string
	defaultImage  string
	containerName string
	useLocal      bool
	runCount      int
	eventHandler  func(ExecRecord)
}

func NewSandboxEngine(cfg Config) (*SandboxEngine, error) {
	if cfg.WorkspaceDir == "" {
		cfg.WorkspaceDir = ".nexss_workspace"
	}

	absWorkDir, err := filepath.Abs(cfg.WorkspaceDir)
	if err != nil {
		return nil, fmt.Errorf("resolve workspace dir: %w", err)
	}

	if err := os.MkdirAll(absWorkDir, 0o755); err != nil {
		return nil, fmt.Errorf("create workspace dir: %w", err)
	}

	image := cfg.DefaultImage
	if image == "" {
		image = "alpine:latest"
	}

	useLocal := false
	probeCtx, cancelProbe := context.WithTimeout(context.Background(), podmanProbeTimeout)
	if _, err := exec.CommandContext(probeCtx, "podman", "version").Output(); err != nil {
		if !cfg.AllowLocalFallback {
			cancelProbe()
			return nil, xerr.Unavailable("podman is missing and local fallback is not allowed", err)
		}
		useLocal = true
	}
	cancelProbe()

	var b [4]byte
	_, _ = rand.Read(b[:])
	containerName := fmt.Sprintf("nexss-sandbox-%s-%d", hex.EncodeToString(b[:]), time.Now().UnixNano())

	engine := &SandboxEngine{
		workspaceDir:  absWorkDir,
		defaultImage:  image,
		containerName: containerName,
		useLocal:      useLocal,
		eventHandler:  cfg.EventHandler,
	}

	if !useLocal {
		if err := engine.ensureWorkspaceContainer(context.Background()); err != nil {
			if cfg.AllowLocalFallback {
				engine.useLocal = true
			} else {
				return nil, fmt.Errorf("failed starting podman container: %w", err)
			}
		}
	}

	return engine, nil
}

// NewPodmanSandboxEngine is retained for compatibility. New code should
// call NewSandboxEngine.
//
// Deprecated: use NewSandboxEngine.
func NewPodmanSandboxEngine(cfg Config) (*SandboxEngine, error) {
	return NewSandboxEngine(cfg)
}

func (p *SandboxEngine) Name() string { return "podman-sandbox-engine" }

func (p *SandboxEngine) ensureWorkspaceContainer(ctx context.Context) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	// #nosec G204 -- containerName is generated internally by NewSandboxEngine.
	checkCmd := exec.CommandContext(ctx, "podman", "ps", "--filter", "name="+p.containerName, "--format", "{{.Names}}")
	out, checkErr := checkCmd.Output()
	if checkErr != nil {
		slog.Debug("podman: ps check failed", "err", checkErr)
	}
	if strings.Contains(string(out), p.containerName) {
		return nil
	}

	// #nosec G204 -- containerName is generated internally by NewSandboxEngine.
	if err := exec.CommandContext(ctx, "podman", "start", p.containerName).Run(); err == nil {
		return nil
	}

	// #nosec G204 -- containerName is generated internally by NewSandboxEngine.
	if rmErr := exec.CommandContext(ctx, "podman", "rm", "-f", p.containerName).Run(); rmErr != nil {
		slog.Debug("podman: pre-run cleanup failed", "err", rmErr)
	}

	runArgs := []string{
		"run", "-d",
		"--name", p.containerName,
		"--memory", "1024m",
		"--cpus", "2.0",
		"--pids-limit", "256",
		"--network", "none",
		"--read-only",
		"--security-opt", "no-new-privileges",
		"-v", p.workspaceDir + ":/workspace:Z",
		"-w", "/workspace",
		"--tmpfs", "/tmp:rw,exec,nosuid,size=256m",
		p.defaultImage,
		"sleep", "infinity",
	}

	if out, err := exec.CommandContext(ctx, "podman", runArgs...).CombinedOutput(); err != nil {
		return fmt.Errorf("podman run failed: %w: %s", err, string(out))
	}

	return nil
}

func (p *SandboxEngine) applyResourceLimits(ctx context.Context, profile sandbox.Profile) {
	args := []string{"update"}
	if profile.MemoryMB > 0 {
		args = append(args, "--memory", strconv.Itoa(profile.MemoryMB)+"m")
	}
	if profile.CPUs > 0 {
		args = append(args, "--cpus", strconv.FormatFloat(profile.CPUs, 'f', -1, 64))
	}
	if profile.PidsLimit > 0 {
		args = append(args, "--pids-limit", strconv.Itoa(profile.PidsLimit))
	}
	args = append(args, p.containerName)

	if err := exec.CommandContext(ctx, "podman", args...).Run(); err != nil {
		slog.Debug("podman: update resource limits failed", "err", err)
	}
}

func (p *SandboxEngine) emit(rec ExecRecord) {
	if p.eventHandler != nil {
		p.eventHandler(rec)
	}
}

func (p *SandboxEngine) Run(ctx context.Context, _ string, profile sandbox.Profile, command sandbox.Command) (sandbox.ExecutionResult, error) {
	if len(command.Argv) == 0 {
		return sandbox.ExecutionResult{ExitCode: 1, Stderr: "empty command"}, nil
	}

	imageUsed := profile.Image
	if imageUsed == "" {
		imageUsed = p.defaultImage
	}

	var cmd *exec.Cmd

	containerLabel := p.containerName

	if p.useLocal {
		// #nosec G204 -- Executing the supplied argv is this engine's contract; no shell is involved.
		cmd = exec.CommandContext(ctx, command.Argv[0], command.Argv[1:]...)
		cmd.Dir = p.workspaceDir
		if len(command.Env) > 0 {
			cmd.Env = append(os.Environ(), command.Env...)
		}
		containerLabel = "local"
	} else {
		if err := p.ensureWorkspaceContainer(ctx); err != nil {
			return sandbox.ExecutionResult{}, err
		}
		p.applyResourceLimits(ctx, profile)

		execArgs := []string{
			"exec", "-i",
			"-w", profile.Workspace,
		}

		if profile.User != "" {
			execArgs = append(execArgs, "--user", profile.User)
		}

		for _, e := range command.Env {
			execArgs = append(execArgs, "-e", e)
		}

		execArgs = append(execArgs, p.containerName)
		execArgs = append(execArgs, command.Argv...)

		cmd = exec.CommandContext(ctx, "podman", execArgs...)
	}

	if len(command.Stdin) > 0 {
		cmd.Stdin = bytes.NewReader(command.Stdin)
	}

	rec := ExecRecord{
		Command:   command.Argv[0],
		Args:      command.Argv[1:],
		Image:     imageUsed,
		Container: containerLabel,
		Started:   true,
	}
	p.emit(rec)

	exitCode, stdout, stderr, dur := p.runStreaming(cmd, rec)

	rec.Started = false
	rec.ExitCode = exitCode
	rec.Stdout = stdout
	rec.Stderr = stderr
	rec.Duration = dur
	p.emit(rec)

	p.mu.Lock()
	p.runCount++
	p.mu.Unlock()

	return sandbox.ExecutionResult{
		ExitCode: exitCode,
		Stdout:   stdout,
		Stderr:   stderr,
		Duration: dur,
	}, nil
}

func (p *SandboxEngine) runStreaming(cmd *exec.Cmd, rec ExecRecord) (exitCode int, stdout, stderr string, duration time.Duration) {
	start := time.Now()

	stdoutPipe, err := cmd.StdoutPipe()
	if err != nil {
		return 1, "", err.Error(), 0
	}

	stderrPipe, err := cmd.StderrPipe()
	if err != nil {
		return 1, "", err.Error(), 0
	}

	if err := cmd.Start(); err != nil {
		return 1, "", err.Error(), 0
	}

	var stdoutBuf, stderrBuf bytes.Buffer
	var wg sync.WaitGroup

	wg.Add(2)
	go func() {
		defer wg.Done()
		drainStream(stdoutPipe, &stdoutBuf, func(line string) {
			r := rec
			r.Stream = "stdout"
			r.Line = line
			p.emit(r)
		})
	}()
	go func() {
		defer wg.Done()
		drainStream(stderrPipe, &stderrBuf, func(line string) {
			r := rec
			r.Stream = "stderr"
			r.Line = line
			p.emit(r)
		})
	}()

	wg.Wait()
	runErr := cmd.Wait()
	duration = time.Since(start)

	if runErr != nil {
		exitErr := &exec.ExitError{}
		if errors.As(runErr, &exitErr) {
			exitCode = exitErr.ExitCode()
		} else {
			exitCode = 1
		}
	}

	return exitCode, stdoutBuf.String(), stderrBuf.String(), duration
}

func drainStream(r io.Reader, buf *bytes.Buffer, emit func(line string)) {
	scanner := bufio.NewScanner(io.TeeReader(r, buf))
	scanner.Buffer(make([]byte, 64*1024), 1<<20)
	for scanner.Scan() {
		emit(scanner.Text())
	}
}

func (p *SandboxEngine) WriteFile(_ context.Context, _ string, profile sandbox.Profile, relativePath string, content []byte) error {
	profile.ApplyDefaults()
	workspace, err := sandbox.OpenWorkspaceFS(p.workspaceDir, profile.MaxFileBytes)
	if err != nil {
		return err
	}
	defer workspace.Close()
	return workspace.WriteFile(relativePath, content)
}

func (p *SandboxEngine) ReadFile(_ context.Context, _ string, profile sandbox.Profile, relativePath string) ([]byte, error) {
	profile.ApplyDefaults()
	workspace, err := sandbox.OpenWorkspaceFS(p.workspaceDir, profile.MaxFileBytes)
	if err != nil {
		return nil, err
	}
	defer workspace.Close()
	return workspace.ReadFile(relativePath)
}

func (p *SandboxEngine) Reset(_ context.Context, _ string) error {
	files, err := os.ReadDir(p.workspaceDir)
	if err != nil {
		return err
	}
	for _, f := range files {
		if rmErr := os.RemoveAll(filepath.Join(p.workspaceDir, f.Name())); rmErr != nil {
			slog.Debug("podman: workspace cleanup failed", "name", f.Name(), "err", rmErr)
		}
	}
	return nil
}

func (p *SandboxEngine) Close() error {
	if !p.useLocal {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		// #nosec G204 -- containerName is generated internally by NewSandboxEngine.
		if err := exec.CommandContext(ctx, "podman", "rm", "-f", p.containerName).Run(); err != nil {
			slog.Debug("podman: remove container failed", "err", err)
		}
	}
	return nil
}
