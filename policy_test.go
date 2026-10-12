package sandbox_test

import (
	"strings"
	"testing"

	"github.com/nexssp/sandbox"
)

// TestStaticPolicy_RejectsWeakProfile verifies every boundary
// weakening condition is rejected. Adding a new escape vector in a
// profile should fail here before it ever reaches an engine.
func TestStaticPolicy_RejectsWeakProfile(t *testing.T) {
	t.Parallel()

	base := sandbox.Profile{
		Name:               "strict",
		Image:              "alpine:latest",
		MemoryMB:           512,
		CPUs:               1.0,
		PidsLimit:          64,
		MaxWallTime:        60_000_000_000, // 60s
		MaxOutputBytes:     1 << 20,
		MaxFileBytes:       1 << 20,
		MaxCommandArgs:     64,
		MaxCommandArgBytes: 32 << 10,
		NetworkMode:        "none",
		ReadOnlyRootFS:     true,
		AllowedExecutables: []string{"go"},
	}

	cases := []struct {
		name   string
		mutate func(*sandbox.Profile)
	}{
		{"empty name", func(p *sandbox.Profile) { p.Name = "" }},
		{"empty image", func(p *sandbox.Profile) { p.Image = "" }},
		{"host network", func(p *sandbox.Profile) { p.NetworkMode = "host" }},
		{"writable rootfs", func(p *sandbox.Profile) { p.ReadOnlyRootFS = false }},
		{"zero memory", func(p *sandbox.Profile) { p.MemoryMB = 0 }},
		{"zero cpus", func(p *sandbox.Profile) { p.CPUs = 0 }},
		{"zero pids", func(p *sandbox.Profile) { p.PidsLimit = 0 }},
		{"zero wall time", func(p *sandbox.Profile) { p.MaxWallTime = 0 }},
		{"zero output", func(p *sandbox.Profile) { p.MaxOutputBytes = 0 }},
		{"zero file", func(p *sandbox.Profile) { p.MaxFileBytes = 0 }},
		{"zero command args", func(p *sandbox.Profile) { p.MaxCommandArgs = 0 }},
		{"zero command arg bytes", func(p *sandbox.Profile) { p.MaxCommandArgBytes = 0 }},
		{"no executables", func(p *sandbox.Profile) { p.AllowedExecutables = nil }},
	}

	policy := sandbox.StaticPolicy{}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			p := base
			c.mutate(&p)
			if err := policy.ValidateProfile(p); err == nil {
				t.Fatal("expected rejection, got nil")
			}
		})
	}
}

// TestStaticPolicy_AcceptsStrictProfile verifies a properly-locked
// profile passes validation.
func TestStaticPolicy_AcceptsStrictProfile(t *testing.T) {
	t.Parallel()

	p := sandbox.Profile{
		Name:               "strict",
		Image:              "alpine:latest",
		MemoryMB:           512,
		CPUs:               1.0,
		PidsLimit:          64,
		MaxWallTime:        60_000_000_000,
		MaxOutputBytes:     1 << 20,
		MaxFileBytes:       1 << 20,
		MaxCommandArgs:     64,
		MaxCommandArgBytes: 32 << 10,
		NetworkMode:        "none",
		ReadOnlyRootFS:     true,
		AllowedExecutables: []string{"go"},
	}
	policy := sandbox.StaticPolicy{}
	if err := policy.ValidateProfile(p); err != nil {
		t.Fatalf("expected accept, got %v", err)
	}
}

// TestStaticPolicy_RejectsDisallowedExecutable verifies the executable
// allowlist is enforced.
func TestStaticPolicy_RejectsDisallowedExecutable(t *testing.T) {
	t.Parallel()

	p := sandbox.Profile{
		Name:               "strict",
		AllowedExecutables: []string{"go", "git"},
	}
	policy := sandbox.StaticPolicy{}

	if err := policy.ValidateCommand(p, (sandbox.Command{Argv: []string{"rm", "-rf"}})); err == nil {
		t.Fatal("expected rejection of 'rm'")
	}
	if err := policy.ValidateCommand(p, (sandbox.Command{Argv: []string{"go", "test"}})); err != nil {
		t.Fatalf("expected accept of 'go', got %v", err)
	}
}

func TestStaticPolicy_ValidatesEnvironmentAllowlist(t *testing.T) {
	t.Parallel()

	policy := sandbox.StaticPolicy{}
	p := sandbox.Profile{AllowedExecutables: []string{"go"}, AllowedEnvKeys: []string{"GOCACHE"}}
	if err := policy.ValidateCommand(p, sandbox.Command{Argv: []string{"go", "test"}, Env: []string{"GOCACHE=/tmp/cache"}}); err != nil {
		t.Fatalf("expected allowlisted environment entry to pass, got %v", err)
	}
	for _, env := range []string{"API_KEY=secret", "GOCACHE", "GOCACHE=/tmp\x00cache"} {
		if err := policy.ValidateCommand(p, sandbox.Command{Argv: []string{"go"}, Env: []string{env}}); err == nil {
			t.Errorf("expected environment entry %q to be rejected", env)
		}
	}
}

// TestStaticPolicy_RejectsPathLikeExecutable verifies an attacker
// can't bypass the allowlist with a path.
func TestStaticPolicy_RejectsPathLikeExecutable(t *testing.T) {
	t.Parallel()

	p := sandbox.Profile{
		Name:               "strict",
		AllowedExecutables: []string{"go"},
	}
	policy := sandbox.StaticPolicy{}

	attacks := []string{
		"/bin/sh",
		"./go",
		"../bin/go",
		`C:\Windows\system32\cmd.exe`,
	}
	for _, exe := range attacks {
		err := policy.ValidateCommand(p, sandbox.Command{Argv: []string{exe}})
		if err == nil {
			t.Fatalf("expected rejection of %q", exe)
		}
		if !strings.Contains(err.Error(), "bare name") && !strings.Contains(err.Error(), "allowlist") {
			t.Fatalf("wrong error for %q: %v", exe, err)
		}
	}
}

// TestStaticPolicy_RejectsTraversalInWritePath verifies the write
// path cannot escape the workspace.
func TestStaticPolicy_RejectsTraversalInWritePath(t *testing.T) {
	t.Parallel()

	p := sandbox.Profile{Name: "strict", MaxFileBytes: 1 << 20}
	policy := sandbox.StaticPolicy{}

	attacks := []string{
		"../escape.txt",
		"../../etc/passwd",
		"/etc/shadow",
		`..\windows\system32`,
	}
	for _, path := range attacks {
		err := policy.ValidateWrite(p, path, 100)
		if err == nil {
			t.Fatalf("expected rejection of %q", path)
		}
	}
}

// TestPermissivePolicy_AlwaysAccepts verifies PermissivePolicy is a
// pure no-op. This is the trust escape hatch — it must never reject.
func TestPermissivePolicy_AlwaysAccepts(t *testing.T) {
	t.Parallel()

	policy := sandbox.PermissivePolicy{}
	p := sandbox.Profile{} // intentionally empty / weak

	if err := policy.ValidateProfile(p); err != nil {
		t.Fatalf("ValidateProfile: %v", err)
	}
	if err := policy.ValidateCommand(p, sandbox.Command{Argv: []string{"anything"}}); err != nil {
		t.Fatalf("ValidateCommand: %v", err)
	}
	if err := policy.ValidateWrite(p, "../escape.txt", 1<<30); err != nil {
		t.Fatalf("ValidateWrite: %v", err)
	}
}
