package nexssflow

import (
	"context"
	"fmt"
	"strings"

	"github.com/nexssp/flow/compiler"
)

func newSandboxDirective() compiler.Directive {
	return compiler.Directive{
		Name:    "sandbox",
		Example: `@sandbox builder { image: "golang:1.26-alpine", memory_mb: 2048 }`,
		Handler: handleSandbox,
	}
}

func handleSandbox(_ context.Context, req compiler.DirectiveReq) (compiler.DirectiveRes, error) {
	line := strings.TrimSpace(req.Lines[req.I])
	rest := strings.TrimSpace(strings.TrimPrefix(line, "@sandbox"))

	position := compiler.Position{File: req.File, Line: req.I + 1}

	openBrace := strings.IndexByte(rest, '{')
	if openBrace <= 0 {
		return compiler.DirectiveRes{}, compiler.SourceError(position,
			"@sandbox: expected `NAME { ... }`")
	}

	name := strings.TrimSpace(rest[:openBrace])
	if name == "" {
		return compiler.DirectiveRes{}, compiler.SourceError(position,
			"@sandbox: name is required before '{'")
	}

	options, next, err := compiler.ParseBlockOptions(req.Lines, req.I)
	if err != nil {
		return compiler.DirectiveRes{}, compiler.SourceError(position,
			"@sandbox %s: %v", name, err)
	}

	decl, err := parseSandboxDeclaration(name, options, position)
	if err != nil {
		return compiler.DirectiveRes{}, err
	}

	if err := ensureUniqueSandboxName(req.Out, decl.Name, position); err != nil {
		return compiler.DirectiveRes{}, err
	}

	req.Out["sandboxes"] = append(SandboxDeclarationsFromMeta(req.Out), decl)

	return compiler.DirectiveRes{Next: next}, nil
}

func parseSandboxDeclaration(name string, options map[string]string, position compiler.Position) (SandboxDecl, error) {
	image := options["image"]
	if image == "" {
		return SandboxDecl{}, compiler.SourceError(position,
			"@sandbox %s: image is required", name)
	}

	memoryMB, err := parseIntOption(options, "memory_mb", name, position)
	if err != nil {
		return SandboxDecl{}, err
	}

	cpus, err := parseFloatOption(options, "cpus", name, position)
	if err != nil {
		return SandboxDecl{}, err
	}

	pidsLimit, err := parseIntOption(options, "pids_limit", name, position)
	if err != nil {
		return SandboxDecl{}, err
	}

	networkMode := options["network_mode"]
	if networkMode == "" {
		networkMode = "none"
	}

	if err := validateSandboxOptionKeys(name, options, position); err != nil {
		return SandboxDecl{}, err
	}

	return SandboxDecl{
		Name:               name,
		Image:              image,
		MemoryMB:           memoryMB,
		CPUs:               cpus,
		PidsLimit:          pidsLimit,
		NetworkMode:        networkMode,
		User:               options["user"],
		Workspace:          options["workspace"],
		AllowedExecutables: splitCSV(options["allowed_executables"]),
		AllowedEnvKeys:     splitCSV(options["allowed_env_keys"]),
		Position:           position,
	}, nil
}

func parseIntOption(options map[string]string, key, sandboxName string, position compiler.Position) (int, error) {
	raw := options[key]
	if raw == "" {
		return 0, nil
	}
	var out int
	if _, err := fmt.Sscanf(raw, "%d", &out); err != nil {
		return 0, compiler.SourceError(position,
			"@sandbox %s: %s must be an integer", sandboxName, key)
	}
	return out, nil
}

func parseFloatOption(options map[string]string, key, sandboxName string, position compiler.Position) (float64, error) {
	raw := options[key]
	if raw == "" {
		return 0, nil
	}
	var out float64
	if _, err := fmt.Sscanf(raw, "%f", &out); err != nil {
		return 0, compiler.SourceError(position,
			"@sandbox %s: %s must be a number", sandboxName, key)
	}
	return out, nil
}

var allowedSandboxOptionKeys = map[string]struct{}{
	"image":               {},
	"memory_mb":           {},
	"cpus":                {},
	"pids_limit":          {},
	"network_mode":        {},
	"user":                {},
	"workspace":           {},
	"allowed_executables": {},
	"allowed_env_keys":    {},
}

func validateSandboxOptionKeys(name string, options map[string]string, position compiler.Position) error {
	for key := range options {
		if _, ok := allowedSandboxOptionKeys[key]; ok {
			continue
		}
		return compiler.SourceError(position,
			"@sandbox %s: unknown attribute %q", name, key)
	}
	return nil
}

func ensureUniqueSandboxName(meta map[string]any, name string, position compiler.Position) error {
	for i := range SandboxDeclarationsFromMeta(meta) {
		if SandboxDeclarationsFromMeta(meta)[i].Name == name {
			return compiler.SourceError(position,
				"@sandbox %s: duplicate declaration", name)
		}
	}
	return nil
}

func splitCSV(raw string) []string {
	if raw == "" {
		return nil
	}
	var out []string
	for part := range strings.SplitSeq(raw, ",") {
		if part = strings.TrimSpace(part); part != "" {
			out = append(out, part)
		}
	}
	return out
}

// SandboxDeclarationsFromMeta returns the @sandbox declarations recorded
// during preprocessing.
func SandboxDeclarationsFromMeta(meta map[string]any) []SandboxDecl {
	if meta == nil {
		return nil
	}
	decls, _ := meta["sandboxes"].([]SandboxDecl)
	return decls
}

// DeclarationsFromMeta is retained for compatibility.
//
// Deprecated: use SandboxDeclarationsFromMeta.
func DeclarationsFromMeta(meta map[string]any) []SandboxDecl {
	return SandboxDeclarationsFromMeta(meta)
}
