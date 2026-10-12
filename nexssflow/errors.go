package nexssflow

import "fmt"

func errUnknownEngine(name string) error {
	return fmt.Errorf(
		"sandbox: unknown engine %q (allowed: docker, podman, inprocess, mock)", name,
	)
}
