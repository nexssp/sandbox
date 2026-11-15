//go:build windows

package runtimecleanup

import (
	"errors"
	"os"

	"golang.org/x/sys/windows"
)

var errLeaseHeld = errors.New("container lease is held")

func lockLeaseFile(file *os.File, nonblocking bool) (func() error, error) {
	overlapped := &windows.Overlapped{}
	flags := uint32(windows.LOCKFILE_EXCLUSIVE_LOCK)
	if nonblocking {
		flags |= windows.LOCKFILE_FAIL_IMMEDIATELY
	}
	if err := windows.LockFileEx(windows.Handle(file.Fd()), flags, 0, 1, 0, overlapped); err != nil {
		if errors.Is(err, windows.ERROR_LOCK_VIOLATION) {
			return nil, errLeaseHeld
		}
		return nil, err
	}
	return func() error {
		return windows.UnlockFileEx(windows.Handle(file.Fd()), 0, 1, 0, overlapped)
	}, nil
}
