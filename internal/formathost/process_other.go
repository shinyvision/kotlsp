//go:build !linux

package formathost

import "os/exec"

func configureProcess(command *exec.Cmd) {}
