//go:build !linux

package index

import "os/exec"

func configureCompilerProcess(command *exec.Cmd) { limitCompilerEnvironment(command) }
