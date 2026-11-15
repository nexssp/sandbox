//go:build unix

package runtimecleanup

import (
	"errors"
	"os"
	"syscall"
)

var errLeaseHeld = errors.New("container lease is held")

func lockLeaseFile(file *os.File, nonblocking bool) (func() error, error) {
	flags := syscall.LOCK_EX
	if nonblocking {
		flags |= syscall.LOCK_NB
	}
	if err := syscall.Flock(int(file.Fd()), flags); err != nil {
		if errors.Is(err, syscall.EWOULDBLOCK) || errors.Is(err, syscall.EAGAIN) {
			return nil, errLeaseHeld
		}
		return nil, err
	}
	return func() error { return syscall.Flock(int(file.Fd()), syscall.LOCK_UN) }, nil
}
