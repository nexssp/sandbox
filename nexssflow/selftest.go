package nexssflow

import "github.com/nexssp/flow/compiler"

// selftest exercises the bundle against the in-process mock engine so
// the `nflow self test` command can verify the sandbox bundle without
// requiring docker or podman on the host.
func selftest() []compiler.SelfTestSection {
	return []compiler.SelfTestSection{
		{
			Name: "sandbox",
			Features: []compiler.SelfTestFeature{
				{
					Name:   "exec via mock engine",
					Source: "sandbox/exec_mock.nflow",
					DSL: `@require github.com/nexssp/sandbox/nexssflow { engine: "mock", workspace: ".sandbox_selftest" }

{ command: "go", args: ["test", "./..."] } -> sandbox.exec
`,
				},
				{
					Name:   "named sandbox declaration",
					Source: "sandbox/named.nflow",
					DSL: `@require github.com/nexssp/sandbox/nexssflow { engine: "mock", workspace: ".sandbox_selftest" }

@sandbox builder { image: "golang:1.26-alpine", memory_mb: 1024 }

{ command: "go", args: ["build", "./..."] } -> sandbox.builder
`,
				},
				{
					Name:   "require with alias",
					Source: "sandbox/alias.nflow",
					DSL: `@require github.com/nexssp/sandbox/nexssflow as sb { engine: "mock", workspace: ".sandbox_selftest" }

{ command: "gofmt", args: ["main.go"] } -> sb.exec
`,
				},
			},
		},
	}
}
