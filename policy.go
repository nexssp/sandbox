package sandbox

import (
	"errors"
	"fmt"
	"slices"
	"strings"
)

type Policy interface {
	ValidateProfile(profile Profile) error
	ValidateCommand(profile Profile, command Command) error
	ValidateWrite(profile Profile, relativePath string, size int) error
}

type StaticPolicy struct{}

func (StaticPolicy) ValidateProfile(profile Profile) error {
	if strings.TrimSpace(profile.Name) == "" {
		return errors.New("sandbox: profile name is required")
	}

	if strings.TrimSpace(profile.Image) == "" {
		return errors.New("sandbox: profile image is required")
	}

	if profile.NetworkMode != "none" {
		return fmt.Errorf("sandbox: profile %q must use network mode \"none\", got %q", profile.Name, profile.NetworkMode)
	}

	if !profile.ReadOnlyRootFS {
		return fmt.Errorf("sandbox: profile %q must set read_only_root_fs", profile.Name)
	}

	if profile.MemoryMB <= 0 {
		return fmt.Errorf("sandbox: profile %q must set a positive memory limit", profile.Name)
	}

	if profile.CPUs <= 0 {
		return fmt.Errorf("sandbox: profile %q must set a positive CPU limit", profile.Name)
	}

	if profile.PidsLimit <= 0 {
		return fmt.Errorf("sandbox: profile %q must set a positive pids limit", profile.Name)
	}

	if profile.MaxWallTime <= 0 {
		return fmt.Errorf("sandbox: profile %q must set a positive wall time limit", profile.Name)
	}

	if profile.MaxOutputBytes <= 0 {
		return fmt.Errorf("sandbox: profile %q must set a positive output byte limit", profile.Name)
	}

	if profile.MaxFileBytes <= 0 {
		return fmt.Errorf("sandbox: profile %q must set a positive file byte limit", profile.Name)
	}

	if profile.MaxCommandArgs <= 0 {
		return fmt.Errorf("sandbox: profile %q must set a positive command argument count limit", profile.Name)
	}

	if profile.MaxCommandArgBytes <= 0 {
		return fmt.Errorf("sandbox: profile %q must set a positive command argument byte limit", profile.Name)
	}

	if len(profile.AllowedExecutables) == 0 {
		return fmt.Errorf("sandbox: profile %q must allowlist at least one executable", profile.Name)
	}

	return nil
}

func (StaticPolicy) ValidateCommand(profile Profile, command Command) error {
	if len(command.Argv) == 0 {
		return errors.New("sandbox: command argv is empty")
	}

	if profile.MaxCommandArgs > 0 && len(command.Argv) > profile.MaxCommandArgs {
		return fmt.Errorf("sandbox: argv length %d exceeds limit %d", len(command.Argv), profile.MaxCommandArgs)
	}

	executable := command.Argv[0]
	if strings.ContainsAny(executable, `/\`) {
		return fmt.Errorf("sandbox: executable %q must be a bare name, not a path", executable)
	}

	if !slices.Contains(profile.AllowedExecutables, executable) {
		return fmt.Errorf("sandbox: executable %q is not on the profile allowlist", executable)
	}

	for _, arg := range command.Argv {
		if strings.IndexByte(arg, 0) >= 0 {
			return errors.New("sandbox: argv contains a NUL byte")
		}

		if profile.MaxCommandArgBytes > 0 && len(arg) > profile.MaxCommandArgBytes {
			return fmt.Errorf("sandbox: argv element exceeds %d bytes", profile.MaxCommandArgBytes)
		}
	}
	allowedEnv := make(map[string]struct{}, len(profile.AllowedEnvKeys))
	for _, key := range profile.AllowedEnvKeys {
		allowedEnv[key] = struct{}{}
	}
	for _, entry := range command.Env {
		if strings.IndexByte(entry, 0) >= 0 {
			return errors.New("sandbox: environment entry contains a NUL byte")
		}
		key, _, ok := strings.Cut(entry, "=")
		if !ok || key == "" {
			return errors.New("sandbox: environment entry must be KEY=value")
		}
		if _, ok := allowedEnv[key]; !ok {
			return fmt.Errorf("sandbox: environment key %q is not on the profile allowlist", key)
		}
	}

	return nil
}

func (StaticPolicy) ValidateWrite(profile Profile, relativePath string, size int) error {
	if relativePath == "" {
		return errors.New("sandbox: write path is required")
	}

	if strings.HasPrefix(relativePath, "/") || strings.HasPrefix(relativePath, `\`) {
		return fmt.Errorf("sandbox: write path %q must be relative", relativePath)
	}

	if containsParentTraversal(relativePath) {
		return fmt.Errorf("sandbox: write path %q escapes the workspace", relativePath)
	}

	if size < 0 {
		return errors.New("sandbox: write size cannot be negative")
	}

	if profile.MaxFileBytes > 0 && size > profile.MaxFileBytes {
		return fmt.Errorf("sandbox: write size %d exceeds limit %d", size, profile.MaxFileBytes)
	}

	return nil
}

type PermissivePolicy struct{}

func (PermissivePolicy) ValidateProfile(Profile) error          { return nil }
func (PermissivePolicy) ValidateCommand(Profile, Command) error { return nil }
func (PermissivePolicy) ValidateWrite(Profile, string, int) error {
	return nil
}

func containsParentTraversal(path string) bool {
	normalized := strings.ReplaceAll(path, `\`, "/")
	return slices.Contains(strings.Split(normalized, "/"), "..")
}
