//go:build linux

package formathost

import (
	"os/exec"
	"syscall"
)

// configureProcess ends the host with kotlsp: a JVM must not outlive it.
func configureProcess(command *exec.Cmd) {
	command.SysProcAttr = &syscall.SysProcAttr{Pdeathsig: syscall.SIGKILL}
}
