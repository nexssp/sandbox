//go:build !unix && !windows

package runtimecleanup

import (
	"errors"
	"os"
)

var errLeaseHeld = errors.New("container lease is held")

func lockLeaseFile(_ *os.File, _ bool) (func() error, error) {
	return nil, errors.New("container leases are not supported on this platform")
}
