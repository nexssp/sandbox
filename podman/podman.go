package podman

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
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
	WorkspaceDir string
	DefaultImage string
	// Deprecated: retained for source compatibility and ignored. Podman-backed
	// execution never falls back to running commands on the host.
	AllowLocalFallback bool
	EventHandler       func(ExecRecord)
}

// SandboxEngine is the podman-backed implementation of sandbox.Engine.
type SandboxEngine struct {
	mu            sync.RWMutex
	workspaceDir  string
	defaultImage  string
	containerName string
	runCount      int
	eventHandler  func(ExecRecord)
	sessions      map[string]*sandboxSession
}

type sandboxSession struct {
	mu               sync.Mutex
	containerName    string
	workspaceDir     string
	containerCreated bool
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

	probeCtx, cancelProbe := context.WithTimeout(context.Background(), podmanProbeTimeout)
	if _, err := exec.CommandContext(probeCtx, "podman", "version").Output(); err != nil {
		cancelProbe()
		return nil, xerr.Unavailable("podman is unavailable; host fallback is disabled", err)
	}
	cancelProbe()

	var b [4]byte
	_, _ = rand.Read(b[:])
	containerName := fmt.Sprintf("nexss-sandbox-%s-%d", hex.EncodeToString(b[:]), time.Now().UnixNano())

	engine := &SandboxEngine{
		workspaceDir:  absWorkDir,
		defaultImage:  image,
		containerName: containerName,
		eventHandler:  cfg.EventHandler,
		sessions:      make(map[string]*sandboxSession),
	}

	defaultSession := engine.getSession("")
	defaultSession.mu.Lock()
	ensureErr := engine.ensureWorkspaceContainer(context.Background(), defaultSession)
	defaultSession.mu.Unlock()
	if ensureErr != nil {
		return nil, fmt.Errorf("failed starting podman container: %w", ensureErr)
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

func sessionIDKey(sessionID string) string {
	if sessionID == "" {
		return "default"
	}
	return sessionID
}

func sessionDigest(sessionID string) string {
	sum := sha256.Sum256([]byte(sessionIDKey(sessionID)))
	return hex.EncodeToString(sum[:])
}

func (p *SandboxEngine) getSession(sessionID string) *sandboxSession {
	key := sessionIDKey(sessionID)
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.sessions == nil {
		p.sessions = make(map[string]*sandboxSession)
	}
	if session, ok := p.sessions[key]; ok {
		return session
	}
	containerName := p.containerName
	if key != "default" {
		containerName += "-" + sessionDigest(key)
	}
	workspaceDir := filepath.Join(p.workspaceDir, ".sessions", sessionDigest(key))
	if key == "default" {
		workspaceDir = p.workspaceDir
	}
	session := &sandboxSession{
		containerName: containerName,
		workspaceDir:  workspaceDir,
	}
	p.sessions[key] = session
	return session
}

func (p *SandboxEngine) ensureWorkspaceContainer(ctx context.Context, session *sandboxSession) error {
	if err := os.MkdirAll(session.workspaceDir, 0o755); err != nil {
		return fmt.Errorf("create session workspace: %w", err)
	}

	// #nosec G204 -- containerName is generated internally from an engine nonce and a session hash.
	checkCmd := exec.CommandContext(ctx, "podman", "ps", "--filter", "name="+session.containerName, "--format", "{{.Names}}")
	out, checkErr := checkCmd.Output()
	if checkErr != nil {
		slog.Debug("podman: ps check failed", "err", checkErr)
	}
	if slices.Contains(strings.Fields(string(out)), session.containerName) {
		session.containerCreated = true
		return nil
	}

	// #nosec G204 -- containerName is generated internally from an engine nonce and a session hash.
	if err := exec.CommandContext(ctx, "podman", "start", session.containerName).Run(); err == nil {
		session.containerCreated = true
		return nil
	}

	// #nosec G204 -- containerName is generated internally from an engine nonce and a session hash.
	if rmErr := exec.CommandContext(ctx, "podman", "rm", "-f", session.containerName).Run(); rmErr != nil {
		slog.Debug("podman: pre-run cleanup failed", "err", rmErr)
	}

	runArgs := []string{
		"run", "-d",
		"--name", session.containerName,
		"--memory", "1024m",
		"--cpus", "2.0",
		"--pids-limit", "256",
		"--network", "none",
		"--read-only",
		"--security-opt", "no-new-privileges",
		"-v", session.workspaceDir + ":/workspace:Z",
		"-w", "/workspace",
		"--tmpfs", "/tmp:rw,exec,nosuid,size=256m",
		p.defaultImage,
		"sleep", "infinity",
	}

	if out, err := exec.CommandContext(ctx, "podman", runArgs...).CombinedOutput(); err != nil {
		return fmt.Errorf("podman run failed: %w: %s", err, string(out))
	}
	session.containerCreated = true

	return nil
}

func (p *SandboxEngine) applyResourceLimits(ctx context.Context, containerName string, profile sandbox.Profile) error {
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
	args = append(args, containerName)

	if out, err := exec.CommandContext(ctx, "podman", args...).CombinedOutput(); err != nil {
		return fmt.Errorf("podman update resource limits: %w: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

func (p *SandboxEngine) emit(rec ExecRecord) {
	if p.eventHandler != nil {
		p.eventHandler(rec)
	}
}

func (p *SandboxEngine) Run(ctx context.Context, sessionID string, profile sandbox.Profile, command sandbox.Command) (sandbox.ExecutionResult, error) {
	if len(command.Argv) == 0 {
		return sandbox.ExecutionResult{ExitCode: 1, Stderr: "empty command"}, nil
	}
	profile.ApplyDefaults()
	session := p.getSession(sessionID)
	session.mu.Lock()
	defer session.mu.Unlock()

	imageUsed := profile.Image
	if imageUsed == "" {
		imageUsed = p.defaultImage
	}

	var cmd *exec.Cmd

	containerLabel := session.containerName
	if err := p.ensureWorkspaceContainer(ctx, session); err != nil {
		return sandbox.ExecutionResult{}, err
	}
	if err := p.applyResourceLimits(ctx, session.containerName, profile); err != nil {
		return sandbox.ExecutionResult{}, err
	}

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

	execArgs = append(execArgs, session.containerName)
	execArgs = append(execArgs, command.Argv...)

	cmd = exec.CommandContext(ctx, "podman", execArgs...)
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

func (p *SandboxEngine) WriteFile(_ context.Context, sessionID string, profile sandbox.Profile, relativePath string, content []byte) error {
	profile.ApplyDefaults()
	session := p.getSession(sessionID)
	session.mu.Lock()
	defer session.mu.Unlock()
	workspace, err := sandbox.OpenWorkspaceFS(session.workspaceDir, profile.MaxFileBytes)
	if err != nil {
		return err
	}
	defer workspace.Close()
	return workspace.WriteFile(relativePath, content)
}

func (p *SandboxEngine) ReadFile(_ context.Context, sessionID string, profile sandbox.Profile, relativePath string) ([]byte, error) {
	profile.ApplyDefaults()
	session := p.getSession(sessionID)
	session.mu.Lock()
	defer session.mu.Unlock()
	workspace, err := sandbox.OpenWorkspaceFS(session.workspaceDir, profile.MaxFileBytes)
	if err != nil {
		return nil, err
	}
	defer workspace.Close()
	return workspace.ReadFile(relativePath)
}

// Reset removes the selected session's container and workspace. For the default
// session, Reset("") removes everything under the engine's base workspace directory.
func (p *SandboxEngine) Reset(ctx context.Context, sessionID string) error {
	session := p.getSession(sessionID)
	session.mu.Lock()
	defer session.mu.Unlock()

	if session.containerCreated {
		// #nosec G204 -- containerName is generated internally from an engine nonce and a session hash.
		if err := exec.CommandContext(ctx, "podman", "rm", "-f", session.containerName).Run(); err != nil {
			return fmt.Errorf("remove session container %q: %w", session.containerName, err)
		}
		session.containerCreated = false
	}
	if err := os.RemoveAll(session.workspaceDir); err != nil {
		return fmt.Errorf("remove session workspace: %w", err)
	}
	return nil
}

// Close removes session containers while preserving their workspace files.
func (p *SandboxEngine) Close() error {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	p.mu.RLock()
	sessions := make([]*sandboxSession, 0, len(p.sessions))
	for _, session := range p.sessions {
		sessions = append(sessions, session)
	}
	p.mu.RUnlock()

	var closeErr error
	for _, session := range sessions {
		session.mu.Lock()
		if session.containerCreated {
			// #nosec G204 -- containerName is generated internally from an engine nonce and a session hash.
			if err := exec.CommandContext(ctx, "podman", "rm", "-f", session.containerName).Run(); err != nil {
				closeErr = errors.Join(closeErr, fmt.Errorf("remove container %q: %w", session.containerName, err))
			}
			session.containerCreated = false
		}
		session.mu.Unlock()
	}
	return closeErr
}
