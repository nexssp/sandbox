package sandbox

import (
	"context"
	"os"
	"strconv"
	"time"
)

const (
	defaultWorkspace     = "/workspace"
	defaultMemoryMB      = 1024
	defaultCPUs          = 1.0
	defaultPidsLimit     = 64
	defaultOutputLimit   = 1 << 20
	defaultFileLimit     = 5 << 20
	defaultCommandLimit  = 64
	defaultArgBytes      = 32 << 10
	defaultIdleTimeout   = 10 * time.Minute
	defaultWorkspacesDir = "workspaces"
)

// Command represents a single process execution inside the sandbox.
type Command struct {
	Argv  []string `json:"argv"`
	Dir   string   `json:"dir,omitempty"`
	Env   []string `json:"env,omitempty"`
	Stdin []byte   `json:"stdin,omitempty"`
}

type Profile struct {
	Name               string        `json:"name" yaml:"name"`
	Image              string        `json:"image" yaml:"image"`
	MemoryMB           int           `json:"memory_mb" yaml:"memory_mb"`
	CPUs               float64       `json:"cpus" yaml:"cpus"`
	Preinstalled       []string      `json:"preinstalled" yaml:"preinstalled"`
	NetworkMode        string        `json:"network_mode" yaml:"network_mode"`
	User               string        `json:"user" yaml:"user"`
	Workspace          string        `json:"workspace" yaml:"workspace"`
	ReadOnlyRootFS     bool          `json:"read_only_root_fs" yaml:"read_only_root_fs"`
	PidsLimit          int           `json:"pids_limit" yaml:"pids_limit"`
	MaxWallTime        time.Duration `json:"max_wall_time" yaml:"max_wall_time"`
	MaxOutputBytes     int           `json:"max_output_bytes" yaml:"max_output_bytes"`
	MaxFileBytes       int           `json:"max_file_bytes" yaml:"max_file_bytes"`
	MaxCommandArgs     int           `json:"max_command_args" yaml:"max_command_args"`
	MaxCommandArgBytes int           `json:"max_command_arg_bytes" yaml:"max_command_arg_bytes"`
	AllowedExecutables []string      `json:"allowed_executables" yaml:"allowed_executables"`
	AllowedEnvKeys     []string      `json:"allowed_env_keys" yaml:"allowed_env_keys"`
	WritablePaths      []string      `json:"writable_paths" yaml:"writable_paths"`
}

func (p *Profile) ApplyDefaults() {
	if p.MemoryMB <= 0 {
		p.MemoryMB = defaultMemoryMB
	}
	if p.CPUs <= 0 {
		p.CPUs = defaultCPUs
	}
	if p.NetworkMode == "" {
		p.NetworkMode = "none"
	}
	if p.User == "" {
		p.User = runnerUser()
	}
	if p.Workspace == "" {
		p.Workspace = defaultWorkspace
	}
	if p.PidsLimit <= 0 {
		p.PidsLimit = defaultPidsLimit
	}
	if p.MaxWallTime <= 0 {
		p.MaxWallTime = 2 * time.Minute
	}
	if p.MaxOutputBytes <= 0 {
		p.MaxOutputBytes = defaultOutputLimit
	}
	if p.MaxFileBytes <= 0 {
		p.MaxFileBytes = defaultFileLimit
	}
	if p.MaxCommandArgs <= 0 {
		p.MaxCommandArgs = defaultCommandLimit
	}
	if p.MaxCommandArgBytes <= 0 {
		p.MaxCommandArgBytes = defaultArgBytes
	}
	p.ReadOnlyRootFS = true
}

type ExecutionResult struct {
	ExitCode  int           `json:"exit_code"`
	Stdout    string        `json:"stdout"`
	Stderr    string        `json:"stderr"`
	Duration  time.Duration `json:"duration"`
	Truncated bool          `json:"truncated"`
}

// Engine defines the contract for Sandboxing drivers (Podman, Docker, InProcess)
type Engine interface {
	Name() string
	Run(ctx context.Context, sessionID string, profile Profile, command Command) (ExecutionResult, error)
	WriteFile(ctx context.Context, sessionID string, profile Profile, relativePath string, content []byte) error
	ReadFile(ctx context.Context, sessionID string, profile Profile, relativePath string) ([]byte, error)
	Reset(ctx context.Context, sessionID string) error
	Close() error
}

func runnerUser() string {
	uid := os.Geteuid()
	gid := os.Getegid()
	if uid <= 0 || gid <= 0 {
		return "1000:1000"
	}
	return strconv.Itoa(uid) + ":" + strconv.Itoa(gid)
}
