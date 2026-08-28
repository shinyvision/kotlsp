//go:build linux

package index

import (
	"os/exec"
	"syscall"
)

func configureCompilerProcess(command *exec.Cmd) {
	limitCompilerEnvironment(command)
	// Compiler diagnostics are best-effort background children. If the LSP or
	// a test process is killed, do not leave memory-heavy K2/javac processes
	// orphaned and competing with the next foreground editor request.
	command.SysProcAttr = &syscall.SysProcAttr{Pdeathsig: syscall.SIGKILL}
}
