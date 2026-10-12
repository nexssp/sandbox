package sandbox

import (
	"github.com/nexssp/kernel/action"
)

// Library returns the confined workspace filesystem actions as a
// kernel action.Library. Aliases give .nflow authors `read`, `write`,
// and `edit` as short forms of the canonical names.
//
// Passing a nil suite returns an empty library so callers can chain
// the helper unconditionally.
func Library(suite *WorkspaceSuite) action.Library {
	if suite == nil {
		return action.Library{Name: "ai/sandbox"}
	}

	return action.Library{
		Name:        "ai/sandbox",
		Description: "Confined workspace file operations: read_file, write_file, edit_file",
		Actions:     suite.Actions(),
		Aliases: []action.Alias{
			{Canonical: "workspace.read_file", Short: []string{"read", "open", "read_file"}},
			{Canonical: "workspace.write_file", Short: []string{"write", "save_file", "write_file"}},
			{Canonical: "workspace.edit_file", Short: []string{"edit", "edit_file"}},
		},
	}
}
