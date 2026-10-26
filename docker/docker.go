package docker

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

const defaultOutputLimit = 1 << 20

const dockerProbeTimeout = 5 * time.Second

type ExecCommandReq struct {
	Command   string   `json:"command"`
	Args      []string `json:"args"`
	Ephemeral bool     `json:"ephemeral,omitempty"`
	Detach    bool     `json:"detach,omitempty"`
	Ports     []string `json:"ports,omitempty"`
	Image     string   `json:"image,omitempty"`
	Network   bool     `json:"network,omitempty"`
}

type ContainerInspectInfo struct {
	Name      string   `json:"name"`
	Status    string   `json:"status"`
	Image     string   `json:"image"`
	Mount     string   `json:"mount"`
	Processes []string `json:"processes"`
	Memory    string   `json:"memory"`
	PIDs      string   `json:"pids"`
}

// ExecRecord describes a single stage of a sandboxed docker exec.
// It is emitted to the optional event handler during streaming and at
// completion.
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
	// Deprecated: retained for source compatibility and ignored. Docker-backed
	// execution never falls back to running commands on the host.
	AllowLocalFallback bool
	EventHandler       func(ExecRecord)

	CacheDir      string // empty = default under WorkspaceDir
	CacheMaxBytes int64  // <=0 = 5 GiB
	DisableCache  bool   // skip docker commit/save caching
}

// SandboxEngine is the docker-backed implementation of sandbox.Engine.
type SandboxEngine struct {
	mu            sync.RWMutex
	workspaceDir  string
	defaultImage  string
	containerName string
	runCount      int
	activeServers []string
	eventHandler  func(ExecRecord)
	cache         *CacheManager
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
		cfg.WorkspaceDir = "workspace"
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
		image = os.Getenv("SANDBOX_IMAGE")
	}

	if image == "" {
		image = "golang:1.25-alpine"
	}

	probeCtx, cancelProbe := context.WithTimeout(context.Background(), dockerProbeTimeout)
	if _, err := exec.CommandContext(probeCtx, "docker", "version").Output(); err != nil {
		cancelProbe()
		return nil, xerr.Unavailable("docker daemon is unreachable; host fallback is disabled", err)
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
		activeServers: make([]string, 0),
		sessions:      make(map[string]*sandboxSession),
	}

	if !cfg.DisableCache {
		cacheDir := cfg.CacheDir
		if cacheDir == "" {
			cacheDir = filepath.Join(absWorkDir, ".jumalu_cache")
		}

		maxBytes := cfg.CacheMaxBytes
		if maxBytes <= 0 {
			maxBytes = 5 << 30 // 5 GiB
		}

		cm, cacheErr := NewCacheManager(cacheDir, maxBytes, true)
		if cacheErr == nil {
			engine.cache = cm
		}
	}

	defaultSession := engine.getSession("")
	defaultSession.mu.Lock()
	ensureErr := engine.ensureWorkspaceContainer(context.Background(), defaultSession)
	defaultSession.mu.Unlock()
	if ensureErr != nil {
		return nil, fmt.Errorf("failed starting sandbox container: %w", ensureErr)
	}

	return engine, nil
}

// NewDockerSandboxEngine is retained for compatibility. New code should
// call NewSandboxEngine.
//
// Deprecated: use NewSandboxEngine.
func NewDockerSandboxEngine(cfg Config) (*SandboxEngine, error) {
	return NewSandboxEngine(cfg)
}

func (d *SandboxEngine) Name() string { return "docker-sandbox-engine" }

func (d *SandboxEngine) Cache() *CacheManager { return d.cache }

func (d *SandboxEngine) CommitToCache(ctx context.Context, tool, recipe string) error {
	if d.cache == nil || !d.cache.Enabled() {
		return nil
	}

	key := RecipeKey(tool, recipe)
	if d.cache.Has(key) {
		return nil
	}

	_, err := d.cache.CommitAndSave(ctx, d.containerName, key, tool, recipe)

	return err
}

func (d *SandboxEngine) resolveBaseImage(ctx context.Context) string {
	if d.cache == nil || !d.cache.Enabled() {
		return d.defaultImage
	}

	latest, ok := d.cache.Latest()
	if !ok {
		return d.defaultImage
	}

	loadCtx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()

	img, err := d.cache.LoadFromDisk(loadCtx, latest.Key)
	if err != nil {
		return d.defaultImage
	}

	return img
}

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

func (d *SandboxEngine) getSession(sessionID string) *sandboxSession {
	key := sessionIDKey(sessionID)
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.sessions == nil {
		d.sessions = make(map[string]*sandboxSession)
	}
	if session, ok := d.sessions[key]; ok {
		return session
	}
	containerName := d.containerName
	if key != "default" {
		containerName += "-" + sessionDigest(key)
	}
	workspaceDir := filepath.Join(d.workspaceDir, ".sessions", sessionDigest(key))
	if key == "default" {
		workspaceDir = d.workspaceDir
	}
	session := &sandboxSession{
		containerName: containerName,
		workspaceDir:  workspaceDir,
	}
	d.sessions[key] = session
	return session
}

func (d *SandboxEngine) ensureWorkspaceContainer(ctx context.Context, session *sandboxSession) error {
	if err := os.MkdirAll(session.workspaceDir, 0o755); err != nil {
		return fmt.Errorf("create session workspace: %w", err)
	}

	// #nosec G204 -- containerName is generated internally from an engine nonce and a session hash.
	checkCmd := exec.CommandContext(ctx, "docker", "ps", "--filter", "name="+session.containerName, "--format", "{{.Names}}")
	out, checkErr := checkCmd.Output()
	if checkErr != nil {
		slog.Debug("docker: ps check failed", "err", checkErr)
	}
	if slices.Contains(strings.Fields(string(out)), session.containerName) {
		session.containerCreated = true
		return nil
	}

	// #nosec G204 -- containerName is generated internally from an engine nonce and a session hash.
	if err := exec.CommandContext(ctx, "docker", "start", session.containerName).Run(); err == nil {
		session.containerCreated = true
		return nil
	}

	// #nosec G204 -- containerName is generated internally from an engine nonce and a session hash.
	if rmErr := exec.CommandContext(ctx, "docker", "rm", "-f", session.containerName).Run(); rmErr != nil {
		slog.Debug("docker: pre-run cleanup failed", "err", rmErr)
	}

	baseImage := d.resolveBaseImage(ctx)

	runArgs := []string{
		"run", "-d",
		"--name", session.containerName,
		"--memory", "2048m",
		"--cpus", "2.0",
		"--pids-limit", "512",
		"--network", "none",
		"--read-only",
		"--security-opt", "no-new-privileges",
		"-e", "GOCACHE=/tmp/gocache",
		"-e", "TMPDIR=/tmp",
		"-e", "DEBIAN_FRONTEND=noninteractive",
		"-e", "DEBCONF_NOWARNINGS=yes",
		"--tmpfs", "/tmp:rw,exec,nosuid,size=512m",
		"--mount", fmt.Sprintf("type=bind,src=%s,dst=/workspace", session.workspaceDir),
		"-w", "/workspace",
		baseImage,
		"tail", "-f", "/dev/null",
	}

	if out, err := exec.CommandContext(ctx, "docker", runArgs...).CombinedOutput(); err != nil {
		return fmt.Errorf("docker run: %w: %s", err, string(out))
	}
	session.containerCreated = true

	return nil
}

func (d *SandboxEngine) emit(rec ExecRecord) {
	if d.eventHandler != nil {
		d.eventHandler(rec)
	}
}

func drainStream(r io.Reader, buf io.Writer, emit func(line string)) {
	scanner := bufio.NewScanner(io.TeeReader(r, buf))
	scanner.Buffer(make([]byte, 64*1024), 1<<20)

	for scanner.Scan() {
		emit(scanner.Text())
	}
	if scanner.Err() != nil {
		// Preserve any remaining bytes so callers see the full output
		// even when the scanner hit its buffer limit.
		if _, err := io.Copy(io.Discard, r); err != nil {
			slog.Debug("docker: drain remainder failed", "err", err)
		}
	}
}

type boundedBuffer struct {
	mu        sync.Mutex
	data      bytes.Buffer
	maxBytes  int
	truncated bool
}

func newBoundedBuffer(maxBytes int) *boundedBuffer {
	if maxBytes <= 0 {
		maxBytes = defaultOutputLimit
	}
	return &boundedBuffer{maxBytes: maxBytes}
}

func (b *boundedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	written := len(p)
	remaining := b.maxBytes - b.data.Len()
	if remaining > 0 {
		keep := min(len(p), remaining)
		_, _ = b.data.Write(p[:keep])
		if keep < len(p) {
			b.truncated = true
		}
	} else if len(p) > 0 {
		b.truncated = true
	}
	return written, nil
}

func (b *boundedBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.data.String()
}

func (b *boundedBuffer) WasTruncated() bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.truncated
}

func (d *SandboxEngine) runStreaming(
	ctx context.Context,
	cmd *exec.Cmd,
	rec ExecRecord,
	maxOutputBytes int,
) (exitCode int, stdout, stderr string, dur time.Duration, truncated bool) {
	_ = ctx // retained for symmetry; cmd already carries the context
	start := time.Now()

	stdoutPipe, err := cmd.StdoutPipe()
	if err != nil {
		return 1, "", err.Error(), 0, false
	}

	stderrPipe, err := cmd.StderrPipe()
	if err != nil {
		return 1, "", err.Error(), 0, false
	}

	if err := cmd.Start(); err != nil {
		return 1, "", err.Error(), 0, false
	}

	stdoutBuf := newBoundedBuffer(maxOutputBytes)
	stderrBuf := newBoundedBuffer(maxOutputBytes)
	var wg sync.WaitGroup

	wg.Add(2)
	go func() {
		defer wg.Done()

		drainStream(stdoutPipe, stdoutBuf, func(line string) {
			r := rec
			r.Stream = "stdout"
			r.Line = line
			d.emit(r)
		})
	}()
	go func() {
		defer wg.Done()

		drainStream(stderrPipe, stderrBuf, func(line string) {
			r := rec
			r.Stream = "stderr"
			r.Line = line
			d.emit(r)
		})
	}()

	wg.Wait()
	runErr := cmd.Wait()
	dur = time.Since(start)

	if runErr != nil {
		exitErr := &exec.ExitError{}
		if errors.As(runErr, &exitErr) {
			exitCode = exitErr.ExitCode()
		} else {
			exitCode = 1
		}
	}

	return exitCode, stdoutBuf.String(), stderrBuf.String(), dur, stdoutBuf.WasTruncated() || stderrBuf.WasTruncated()
}

func (d *SandboxEngine) ExecAdvanced(ctx context.Context, req ExecCommandReq) (sandbox.ExecutionResult, error) {
	session := d.getSession("")
	session.mu.Lock()
	defer session.mu.Unlock()
	if err := d.ensureWorkspaceContainer(ctx, session); err != nil {
		return sandbox.ExecutionResult{}, err
	}

	d.mu.RLock()
	containerName := session.containerName
	image := d.defaultImage
	handler := d.eventHandler
	d.mu.RUnlock()

	args := append([]string{"exec", containerName, req.Command}, req.Args...)
	cmd := exec.CommandContext(ctx, "docker", args...)

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return sandbox.ExecutionResult{}, err
	}

	stderr, err := cmd.StderrPipe()
	if err != nil {
		return sandbox.ExecutionResult{}, err
	}

	if handler != nil {
		handler(ExecRecord{
			Command: req.Command, Args: req.Args,
			Image: image, Container: containerName, Started: true,
		})
	}

	start := time.Now()

	if err := cmd.Start(); err != nil {
		return sandbox.ExecutionResult{}, err
	}

	var (
		stdoutBuf, stderrBuf strings.Builder
		wg                   sync.WaitGroup
	)

	const chunkSize = 4096

	pump := func(r io.Reader, stream string, dst *strings.Builder) {
		defer wg.Done()

		buf := make([]byte, chunkSize)
		for {
			n, rerr := r.Read(buf)
			if n > 0 {
				dst.Write(buf[:n])

				if handler != nil {
					handler(ExecRecord{
						Command: req.Command, Args: req.Args,
						Container: containerName, Image: image,
						Started: true,
						Stream:  stream,
						Line:    string(buf[:n]),
					})
				}
			}

			if rerr != nil {
				return
			}
		}
	}

	wg.Add(2)

	go pump(stdout, "stdout", &stdoutBuf)
	go pump(stderr, "stderr", &stderrBuf)

	wg.Wait()

	werr := cmd.Wait()
	dur := time.Since(start)

	exitCode := 0

	if werr != nil {
		ee := &exec.ExitError{}
		if errors.As(werr, &ee) {
			exitCode = ee.ExitCode()
		} else {
			exitCode = -1
		}
	}

	res := sandbox.ExecutionResult{
		ExitCode: exitCode,
		Stdout:   stdoutBuf.String(),
		Stderr:   stderrBuf.String(),
		Duration: dur,
	}

	if handler != nil {
		handler(ExecRecord{
			Command: req.Command, Args: req.Args,
			ExitCode: exitCode,
			Stdout:   res.Stdout, Stderr: res.Stderr,
			Duration: dur,
			Image:    image, Container: containerName, Started: false,
		})
	}

	return res, werr
}

func (d *SandboxEngine) Run(ctx context.Context, sessionID string, profile sandbox.Profile, command sandbox.Command) (sandbox.ExecutionResult, error) {
	if len(command.Argv) == 0 {
		return sandbox.ExecutionResult{ExitCode: 1, Stderr: "empty command"}, nil
	}
	profile.ApplyDefaults()
	session := d.getSession(sessionID)
	session.mu.Lock()
	defer session.mu.Unlock()

	imageUsed := profile.Image
	if imageUsed == "" {
		imageUsed = d.defaultImage
	}

	containerLabel := session.containerName
	if err := d.ensureWorkspaceContainer(ctx, session); err != nil {
		return sandbox.ExecutionResult{}, err
	}
	if err := d.applyResourceLimits(ctx, session.containerName, profile); err != nil {
		return sandbox.ExecutionResult{}, err
	}

	execArgs := []string{
		"exec", "-i=false",
		"-w", profile.Workspace,
		"-e", "DEBIAN_FRONTEND=noninteractive",
		"-e", "DEBCONF_NOWARNINGS=yes",
	}

	if profile.User != "" {
		execArgs = append(execArgs, "--user", profile.User)
	}

	for _, e := range command.Env {
		execArgs = append(execArgs, "-e", e)
	}

	execArgs = append(execArgs, session.containerName)
	execArgs = append(execArgs, command.Argv...)

	cmd := exec.CommandContext(ctx, "docker", execArgs...)
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
	d.emit(rec)

	maxOutputBytes := profile.MaxOutputBytes
	if maxOutputBytes <= 0 {
		maxOutputBytes = defaultOutputLimit
	}
	exitCode, stdout, stderr, dur, truncated := d.runStreaming(ctx, cmd, rec, maxOutputBytes)

	rec.Started = false
	rec.ExitCode = exitCode
	rec.Stdout = stdout
	rec.Stderr = stderr
	rec.Duration = dur
	d.emit(rec)

	d.mu.Lock()
	d.runCount++
	d.mu.Unlock()

	return sandbox.ExecutionResult{
		ExitCode:  exitCode,
		Stdout:    stdout,
		Stderr:    stderr,
		Duration:  dur,
		Truncated: truncated,
	}, nil
}

func (d *SandboxEngine) applyResourceLimits(ctx context.Context, containerName string, profile sandbox.Profile) error {
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

	if out, err := exec.CommandContext(ctx, "docker", args...).CombinedOutput(); err != nil {
		return fmt.Errorf("docker update resource limits: %w: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

func (d *SandboxEngine) InspectContainer(ctx context.Context) ContainerInspectInfo {
	session := d.getSession("")
	session.mu.Lock()
	defer session.mu.Unlock()

	// #nosec G204 -- containerName is generated internally from an engine nonce and a session hash.
	psCmd := exec.CommandContext(ctx, "docker", "top", session.containerName)
	psOut, err := psCmd.Output()

	var procs []string

	if err == nil {
		for l := range strings.SplitSeq(string(psOut), "\n") {
			if strings.TrimSpace(l) != "" {
				procs = append(procs, l)
			}
		}
	}

	return ContainerInspectInfo{
		Name:      session.containerName,
		Status:    "Running",
		Image:     d.defaultImage,
		Mount:     session.workspaceDir + " -> /workspace",
		Processes: procs,
		Memory:    "2048 MB",
		PIDs:      "512",
	}
}

func (d *SandboxEngine) Info() string {
	d.mu.RLock()
	defer d.mu.RUnlock()

	mode := fmt.Sprintf("Workspace Container: [%s]", d.containerName)

	active := len(d.activeServers)

	cacheInfo := ""
	if d.cache != nil && d.cache.Enabled() {
		cacheInfo = fmt.Sprintf(" | Cache: %d entries, %.1f MB",
			len(d.cache.List()),
			float64(d.cache.TotalBytes())/(1024*1024),
		)
	}

	return fmt.Sprintf("%s | Image: %s | PIDs: 512 | Services: %d | Execs: %d%s",
		mode, d.defaultImage, active, d.runCount, cacheInfo)
}

func (d *SandboxEngine) WriteFile(_ context.Context, sessionID string, profile sandbox.Profile, relativePath string, content []byte) error {
	profile.ApplyDefaults()
	session := d.getSession(sessionID)
	session.mu.Lock()
	defer session.mu.Unlock()
	workspace, err := sandbox.OpenWorkspaceFS(session.workspaceDir, profile.MaxFileBytes)
	if err != nil {
		return err
	}
	defer workspace.Close()
	return workspace.WriteFile(relativePath, content)
}

func (d *SandboxEngine) ReadFile(_ context.Context, sessionID string, profile sandbox.Profile, relativePath string) ([]byte, error) {
	profile.ApplyDefaults()
	session := d.getSession(sessionID)
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
func (d *SandboxEngine) Reset(ctx context.Context, sessionID string) error {
	session := d.getSession(sessionID)
	session.mu.Lock()
	defer session.mu.Unlock()

	if session.containerCreated {
		// #nosec G204 -- containerName is generated internally from an engine nonce and a session hash.
		if err := exec.CommandContext(ctx, "docker", "rm", "-f", session.containerName).Run(); err != nil {
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
func (d *SandboxEngine) Close() error {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	d.mu.RLock()
	sessions := make([]*sandboxSession, 0, len(d.sessions))
	for _, session := range d.sessions {
		sessions = append(sessions, session)
	}
	servers := append([]string(nil), d.activeServers...)
	d.mu.RUnlock()

	var closeErr error
	for _, session := range sessions {
		session.mu.Lock()
		if session.containerCreated {
			// #nosec G204 -- containerName is generated internally from an engine nonce and a session hash.
			if err := exec.CommandContext(ctx, "docker", "rm", "-f", session.containerName).Run(); err != nil {
				closeErr = errors.Join(closeErr, fmt.Errorf("remove container %q: %w", session.containerName, err))
			}
			session.containerCreated = false
		}
		session.mu.Unlock()
	}
	for _, server := range servers {
		if err := exec.CommandContext(ctx, "docker", "rm", "-f", server).Run(); err != nil {
			closeErr = errors.Join(closeErr, fmt.Errorf("remove server container %q: %w", server, err))
		}
	}
	return closeErr
}
