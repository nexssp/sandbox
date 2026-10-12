package nexssflow

import "github.com/nexssp/flow/compiler"

// SandboxDecl is a parsed `@sandbox NAME { ... }` declaration.
//
// Only Name and Image are required; every other field is optional and
// falls back to the profile defaults (see sandbox.Profile.ApplyDefaults)
// when zero. The Position field carries the source line so materialize
// errors can point back to the originating declaration.
type SandboxDecl struct {
	Name               string
	Image              string
	MemoryMB           int
	CPUs               float64
	PidsLimit          int
	NetworkMode        string
	User               string
	Workspace          string
	AllowedExecutables []string
	AllowedEnvKeys     []string
	Position           compiler.Position
}
