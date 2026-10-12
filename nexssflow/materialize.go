package nexssflow

import (
	"github.com/nexssp/flow/compiler"
	"github.com/nexssp/kernel/action"

	"github.com/nexssp/sandbox"
)

func materialize(engine sandbox.Engine, policy sandbox.Policy) func(req compiler.MaterializeReq) error {
	return func(req compiler.MaterializeReq) error {
		decls := SandboxDeclarationsFromMeta(req.Meta)
		if len(decls) == 0 {
			return nil
		}

		actions := make([]action.AnyAction, 0, len(decls))
		for i := range decls {
			decl := decls[i]
			profile := declToProfile(decl)
			profile.ApplyDefaults()
			actions = append(actions, buildNamedExec(engine, policy, profile))
		}

		return req.Resolver.MountWithAlias(action.Library{
			Name:    "sandbox.named",
			Actions: actions,
		}, req.Alias)
	}
}

func declToProfile(decl SandboxDecl) sandbox.Profile {
	return sandbox.Profile{
		Name:               decl.Name,
		Image:              decl.Image,
		MemoryMB:           decl.MemoryMB,
		CPUs:               decl.CPUs,
		PidsLimit:          decl.PidsLimit,
		NetworkMode:        decl.NetworkMode,
		User:               decl.User,
		Workspace:          decl.Workspace,
		AllowedExecutables: decl.AllowedExecutables,
		AllowedEnvKeys:     decl.AllowedEnvKeys,
	}
}
