package nexssflow

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"strings"
	"time"

	"github.com/nexssp/kernel/action"

	"github.com/nexssp/sandbox"
)

// buildNamedExec creates the action for a single @sandbox declaration.
// The profile is locked at materialize time; callers pass only the
// RunReq at invocation time.
func buildNamedExec(engine sandbox.Engine, policy sandbox.Policy, profile sandbox.Profile) action.AnyAction {
	return action.New("sandbox."+profile.Name, func(ctx context.Context, req map[string]any) (map[string]any, error) {
		return runAndMerge(ctx, engine, policy, profile, req)
	}).
		Description("Sandboxed execution inside profile "+profile.Name).
		Tag("sandbox", profile.Name).
		Build()
}

// buildGenericExec creates the default `sandbox.exec` action that uses
// the global profile from the @require options block. It is what
// `-> sandbox.exec` routes to (or `<alias>.exec` when @require has an alias).
func buildGenericExec(engine sandbox.Engine, policy sandbox.Policy, global GlobalOptions) action.AnyAction {
	profile := sandbox.Profile{
		Name:               "default",
		Image:              global.Image,
		AllowedExecutables: splitAllowedExecutables(global.AllowedExecutables),
		AllowedEnvKeys:     splitAllowedExecutables(global.AllowedEnvKeys),
	}
	profile.ApplyDefaults()
	return action.New("sandbox.exec", func(ctx context.Context, req map[string]any) (map[string]any, error) {
		return runAndMerge(ctx, engine, policy, profile, req)
	}).
		Description("Sandboxed execution via the globally-configured engine").
		Tag("sandbox", "exec").
		Build()
}

func splitAllowedExecutables(raw string) []string {
	var allowed []string
	for executable := range strings.SplitSeq(raw, ",") {
		if executable = strings.TrimSpace(executable); executable != "" {
			allowed = append(allowed, executable)
		}
	}
	return allowed
}

// runAndMerge performs the actual exec and merges the result back into
// the request map so downstream pipeline stages can read exit_code,
// stdout, stderr, duration, and the boolean `passed` flag.
//
// The Policy is consulted before any I/O is done; a rejection returns
// an xerr-typed error so the runner can classify it as Forbidden or
// BadRequest instead of a generic execution failure.
func runAndMerge(
	ctx context.Context,
	engine sandbox.Engine,
	policy sandbox.Policy,
	profile sandbox.Profile,
	req map[string]any,
) (map[string]any, error) {
	var typed RunReq
	if err := action.Assign(&typed, req); err != nil {
		return nil, fmt.Errorf("sandbox: invalid input: %w", err)
	}
	if typed.Command == "" {
		return nil, errors.New("sandbox: command is required")
	}

	if err := policy.ValidateProfile(profile); err != nil {
		return nil, err
	}

	argv := append([]string{typed.Command}, typed.Args...)
	command := sandbox.Command{
		Argv:  argv,
		Env:   typed.Env,
		Stdin: []byte(typed.Stdin),
	}

	if err := policy.ValidateCommand(profile, command); err != nil {
		return nil, err
	}
	for relPath, content := range typed.Files {
		if err := policy.ValidateWrite(profile, relPath, len(content)); err != nil {
			return nil, err
		}
	}

	// Complete every policy check before the first engine call so an
	// invalid later file or command cannot leave earlier writes behind.
	sessID := "flow_" + profile.Name
	for relPath, content := range typed.Files {
		if err := engine.WriteFile(ctx, sessID, profile, relPath, []byte(content)); err != nil {
			return nil, fmt.Errorf("sandbox: write %q: %w", relPath, err)
		}
	}

	timeout := profile.MaxWallTime
	if timeout <= 0 {
		timeout = 2 * time.Minute
	}
	if typed.Timeout > 0 {
		requested := time.Duration(typed.Timeout) * time.Second
		if requested < timeout {
			timeout = requested
		}
	}
	runCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	result, err := engine.Run(runCtx, sessID, profile, command)
	if err != nil {
		return nil, err
	}

	out := make(map[string]any, len(req)+5)
	maps.Copy(out, req)
	out["exit_code"] = result.ExitCode
	out["stdout"] = result.Stdout
	out["stderr"] = result.Stderr
	out["duration"] = result.Duration.String()
	out["passed"] = result.ExitCode == 0
	out["truncated"] = result.Truncated
	return out, nil
}
