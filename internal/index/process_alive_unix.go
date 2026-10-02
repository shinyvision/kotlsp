//go:build !windows

package index

import (
	"errors"
	"syscall"
)

// processAlive reports whether a process with this id exists. A process
// another user owns answers EPERM, which still means it runs.
func processAlive(pid int) bool {
	err := syscall.Kill(pid, 0)
	return err == nil || errors.Is(err, syscall.EPERM)
}
