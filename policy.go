package sandbox

import (
	"fmt"
	"slices"
	"strings"

	"github.com/nexssp/kernel/xerr"
)

type Policy interface {
	ValidateProfile(profile Profile) error
	ValidateCommand(profile Profile, command Command) error
	ValidateWrite(profile Profile, relativePath string, size int) error
}

type StaticPolicy struct{}

func (StaticPolicy) ValidateProfile(profile Profile) error {
	if strings.TrimSpace(profile.Name) == "" {
		return xerr.BadRequest("sandbox: profile name is required")
	}

	if strings.TrimSpace(profile.Image) == "" {
		return xerr.BadRequest("sandbox: profile image is required")
	}

	if profile.NetworkMode != "none" {
		return xerr.BadRequest(fmt.Sprintf("sandbox: profile %q must use network mode \"none\", got %q", profile.Name, profile.NetworkMode))
	}

	if !profile.ReadOnlyRootFS {
		return xerr.BadRequest(fmt.Sprintf("sandbox: profile %q must set read_only_root_fs", profile.Name))
	}

	if profile.MemoryMB <= 0 {
		return xerr.BadRequest(fmt.Sprintf("sandbox: profile %q must set a positive memory limit", profile.Name))
	}

	if profile.CPUs <= 0 {
		return xerr.BadRequest(fmt.Sprintf("sandbox: profile %q must set a positive CPU limit", profile.Name))
	}

	if profile.PidsLimit <= 0 {
		return xerr.BadRequest(fmt.Sprintf("sandbox: profile %q must set a positive pids limit", profile.Name))
	}

	if profile.MaxWallTime <= 0 {
		return xerr.BadRequest(fmt.Sprintf("sandbox: profile %q must set a positive wall time limit", profile.Name))
	}

	if profile.MaxOutputBytes <= 0 {
		return xerr.BadRequest(fmt.Sprintf("sandbox: profile %q must set a positive output byte limit", profile.Name))
	}

	if profile.MaxFileBytes <= 0 {
		return xerr.BadRequest(fmt.Sprintf("sandbox: profile %q must set a positive file byte limit", profile.Name))
	}

	if profile.MaxCommandArgs <= 0 {
		return xerr.BadRequest(fmt.Sprintf("sandbox: profile %q must set a positive command argument count limit", profile.Name))
	}

	if profile.MaxCommandArgBytes <= 0 {
		return xerr.BadRequest(fmt.Sprintf("sandbox: profile %q must set a positive command argument byte limit", profile.Name))
	}

	if len(profile.AllowedExecutables) == 0 {
		return xerr.BadRequest(fmt.Sprintf("sandbox: profile %q must allowlist at least one executable", profile.Name))
	}

	return nil
}

func (StaticPolicy) ValidateCommand(profile Profile, command Command) error {
	if len(command.Argv) == 0 {
		return xerr.BadRequest("sandbox: command argv is empty")
	}

	if profile.MaxCommandArgs > 0 && len(command.Argv) > profile.MaxCommandArgs {
		return xerr.BadRequest(fmt.Sprintf("sandbox: argv length %d exceeds limit %d", len(command.Argv), profile.MaxCommandArgs))
	}

	executable := command.Argv[0]
	if strings.ContainsAny(executable, `/\`) {
		return xerr.BadRequest(fmt.Sprintf("sandbox: executable %q must be a bare name, not a path", executable))
	}

	if !slices.Contains(profile.AllowedExecutables, executable) {
		return xerr.Forbidden(fmt.Sprintf("sandbox: executable %q is not on the profile allowlist", executable))
	}

	for _, arg := range command.Argv {
		if strings.IndexByte(arg, 0) >= 0 {
			return xerr.BadRequest("sandbox: argv contains a NUL byte")
		}

		if profile.MaxCommandArgBytes > 0 && len(arg) > profile.MaxCommandArgBytes {
			return xerr.BadRequest(fmt.Sprintf("sandbox: argv element exceeds %d bytes", profile.MaxCommandArgBytes))
		}
	}
	allowedEnv := make(map[string]struct{}, len(profile.AllowedEnvKeys))
	for _, key := range profile.AllowedEnvKeys {
		allowedEnv[key] = struct{}{}
	}
	for _, entry := range command.Env {
		if strings.IndexByte(entry, 0) >= 0 {
			return xerr.BadRequest("sandbox: environment entry contains a NUL byte")
		}
		key, _, ok := strings.Cut(entry, "=")
		if !ok || key == "" {
			return xerr.BadRequest("sandbox: environment entry must be KEY=value")
		}
		if _, ok := allowedEnv[key]; !ok {
			return xerr.Forbidden(fmt.Sprintf("sandbox: environment key %q is not on the profile allowlist", key))
		}
	}

	return nil
}

func (StaticPolicy) ValidateWrite(profile Profile, relativePath string, size int) error {
	if relativePath == "" {
		return xerr.BadRequest("sandbox: write path is required")
	}

	if strings.HasPrefix(relativePath, "/") || strings.HasPrefix(relativePath, `\`) {
		return xerr.Forbidden(fmt.Sprintf("sandbox: write path %q must be relative", relativePath))
	}

	if containsParentTraversal(relativePath) {
		return xerr.Forbidden(fmt.Sprintf("sandbox: write path %q escapes the workspace", relativePath))
	}

	if size < 0 {
		return xerr.BadRequest("sandbox: write size cannot be negative")
	}

	if profile.MaxFileBytes > 0 && size > profile.MaxFileBytes {
		return xerr.BadRequest(fmt.Sprintf("sandbox: write size %d exceeds limit %d", size, profile.MaxFileBytes))
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
