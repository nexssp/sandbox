package nexssflow

import (
	"context"
	"maps"
	"strings"
	"time"

	"github.com/nexssp/flow/compiler/contracts"
	"github.com/nexssp/kernel/action"
	"github.com/nexssp/kernel/xerr"
	"github.com/nexssp/kernel/xfile"

	"github.com/nexssp/sandbox"
)

// buildNamedExec creates the action for a single @sandbox declaration.
// The profile is locked at materialize time; callers pass only the
// RunReq at invocation time.
func buildNamedExec(engine sandbox.Engine, policy sandbox.Policy, profile sandbox.Profile, resolver xfile.Resolver) action.AnyAction {
	return action.New("sandbox."+profile.Name, func(ctx context.Context, req map[string]any) (map[string]any, error) {
		return runAndMergeWithFileResolver(ctx, engine, policy, profile, resolver, req)
	}).
		Description("Sandboxed execution inside profile "+profile.Name).
		Tag("sandbox", profile.Name).
		Build()
}

// buildGenericExec creates the default `sandbox.exec` action that uses
// the global profile from the @require options block. It is what
// `-> sandbox.exec` routes to (or `<alias>.exec` when @require has an alias).
func buildGenericExec(engine sandbox.Engine, policy sandbox.Policy, global GlobalOptions, resolver xfile.Resolver) action.AnyAction {
	profile := sandbox.Profile{
		Name:               "default",
		Image:              global.Image,
		AllowedExecutables: splitAllowedExecutables(global.AllowedExecutables),
		AllowedEnvKeys:     splitAllowedExecutables(global.AllowedEnvKeys),
	}
	profile.ApplyDefaults()
	return action.New("sandbox.exec", func(ctx context.Context, req map[string]any) (map[string]any, error) {
		return runAndMergeWithFileResolver(ctx, engine, policy, profile, resolver, req)
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

// runAndMerge retains the resolver-free helper used by existing callers and
// tests. Requests containing file refs fail closed because no resolver is bound.
func runAndMerge(
	ctx context.Context,
	engine sandbox.Engine,
	policy sandbox.Policy,
	profile sandbox.Profile,
	req map[string]any,
) (map[string]any, error) {
	return runAndMergeWithFileResolver(ctx, engine, policy, profile, nil, req)
}

// runAndMergeWithFileResolver performs the actual exec and merges the result
// back into the request map so downstream pipeline stages can read exit_code,
// stdout, stderr, duration, and the boolean `passed` flag.
func runAndMergeWithFileResolver(
	ctx context.Context,
	engine sandbox.Engine,
	policy sandbox.Policy,
	profile sandbox.Profile,
	resolver xfile.Resolver,
	req map[string]any,
) (map[string]any, error) {
	var typed RunReq
	if err := action.Assign(&typed, req); err != nil {
		return nil, xerr.BadRequest("sandbox: invalid input", err)
	}
	if typed.Command == "" {
		return nil, xerr.BadRequest("sandbox: command is required")
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

	// Resolve and validate every reference into private staging files before
	// installing any of them, so a bad later ref cannot leave earlier files.
	if resolver == nil {
		resolver = contracts.FileResolverFromContext(runCtx)
	}
	staged, err := stageFileRefs(runCtx, resolver, policy, profile, typed.Files)
	if err != nil {
		return nil, err
	}
	if staged != nil {
		defer staged.Close()
		if installErr := staged.install(runCtx, engine, "flow_"+profile.Name, profile); installErr != nil {
			return nil, installErr
		}
	}

	result, err := engine.Run(runCtx, "flow_"+profile.Name, profile, command)
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
