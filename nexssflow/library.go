package nexssflow

import (
	"embed"
	"time"

	"github.com/nexssp/flow/compiler"
	"github.com/nexssp/kernel/action"
	"github.com/nexssp/kernel/xerr"
	"github.com/nexssp/kernel/xfile"

	"github.com/nexssp/sandbox"
	"github.com/nexssp/sandbox/docker"
	"github.com/nexssp/sandbox/podman"
)

var fixturesFS embed.FS

const ID = "sandbox"

func init() {
	compiler.Register(ID, Bundle)
}

type GlobalOptions struct {
	Engine             string        `nflow:"engine"       default:"docker"`
	Workspace          string        `nflow:"workspace"    default:".sandbox"`
	Image              string        `nflow:"image"`
	AllowedExecutables string        `nflow:"allowed_executables"`
	AllowedEnvKeys     string        `nflow:"allowed_env_keys"`
	CacheDir           string        `nflow:"cache_dir"`
	CacheMaxMB         int64         `nflow:"cache_max_mb" default:"5120"`
	NoCache            bool          `nflow:"no_cache"`
	StaleContainerAge  time.Duration `nflow:"stale_container_age" default:"24h"`

	// Deprecated: retained for configuration compatibility and ignored. The
	// docker/podman engines fail closed when their runtime is unavailable.
	AllowLocalFallback bool `nflow:"allow_local_fallback"`

	// EnforcePolicy enables the static policy. Default true.
	EnforcePolicy bool `nflow:"enforce_policy" default:"true"`
}

// BlobRef is the Flow-facing name for a provider-neutral xfile.Ref.
type BlobRef = xfile.Ref

type RunReq struct {
	Command string             `json:"command" validate:"required"`
	Args    []string           `json:"args,omitempty"`
	Env     []string           `json:"env,omitempty"`
	Stdin   string             `json:"stdin,omitempty"`
	Files   map[string]BlobRef `json:"files,omitempty"`
	Timeout int                `json:"timeout_seconds,omitempty"`
}

// Bundle builds the standard Sandbox Flow bundle. File references remain
// disabled unless a resolver is explicitly supplied through BundleWithFileResolver.
func Bundle(raw map[string]string) compiler.Bundle {
	return BundleWithFileResolver(raw, nil)
}

// BundleWithFileResolver builds a Sandbox Flow bundle whose file references
// are resolved by the explicitly supplied provider. The resolver receives the
// request context so it can authorize using kernel/xctx scope.
func BundleWithFileResolver(raw map[string]string, resolver xfile.Resolver) compiler.Bundle {
	global, err := compiler.Decode[GlobalOptions](raw)
	if err != nil {
		panic("sandbox bundle: " + err.Error())
	}

	engine, err := buildEngine(global)
	if err != nil {
		kind := xerr.KindFrom(err)
		if kind != xerr.KindUnavailable && kind != xerr.KindBadRequest {
			panic("sandbox bundle: " + err.Error())
		}
		engineName := global.Engine
		if engineName == "" {
			engineName = "docker"
		}
		engineError := err
		if kind == xerr.KindUnavailable {
			engineError = unavailableStartupError(engineName, err)
		}
		engine = startupErrorEngine{
			name: engineName + "-sandbox-engine",
			err:  engineError,
		}
	}

	var policy sandbox.Policy = sandbox.StaticPolicy{}
	if !global.EnforcePolicy {
		policy = sandbox.PermissivePolicy{}
	}

	execAction := buildGenericExec(engine, policy, global, resolver)

	lib := action.Library{
		Name:        ID,
		Description: "Sandboxed command execution via docker, podman, in-process, or mock engines",
		Actions:     []action.AnyAction{execAction},
	}

	return compiler.Bundle{
		ID:          ID,
		Libraries:   []action.Library{lib},
		Directives:  []compiler.Directive{newSandboxDirective()},
		Materialize: materialize(engine, policy, resolver),
		Shutdowns:   []compiler.ShutdownFunc{engineShutdown(engine)},
		SelfTest:    selftest,
		Fixtures:    fixturesFS,
	}
}

func buildEngine(global GlobalOptions) (sandbox.Engine, error) {
	switch global.Engine {
	case "", "docker":
		engine, err := docker.NewSandboxEngine(docker.Config{
			WorkspaceDir:      global.Workspace,
			DefaultImage:      global.Image,
			CacheDir:          global.CacheDir,
			CacheMaxBytes:     global.CacheMaxMB << 20,
			DisableCache:      global.NoCache,
			StaleContainerAge: global.StaleContainerAge,
		})
		if err != nil {
			return nil, err
		}
		return engine, nil
	case "podman":
		engine, err := podman.NewSandboxEngine(podman.Config{
			WorkspaceDir:      global.Workspace,
			DefaultImage:      global.Image,
			StaleContainerAge: global.StaleContainerAge,
		})
		if err != nil {
			return nil, err
		}
		return engine, nil
	case "inprocess":
		return sandbox.NewInProcessEngine(global.Workspace), nil
	case "mock":
		return sandbox.NewMockSandbox(), nil
	default:
		return nil, errUnknownEngine(global.Engine)
	}
}
