//go:build unix

package sesame

import (
	"errors"
	"os/exec"
	"syscall"
)

// ownProcessGroup starts the engine as the leader of a new process group, so
// the FYLO runtime it starts can be ended together with it.
func ownProcessGroup(command *exec.Cmd) {
	command.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
}

// killProcessGroup ends the engine and every process it started.
func killProcessGroup(command *exec.Cmd) {
	_ = syscall.Kill(-command.Process.Pid, syscall.SIGKILL)
}

// processGroupEnded reports whether no process of the engine's group remains.
func processGroupEnded(command *exec.Cmd) bool {
	return errors.Is(syscall.Kill(-command.Process.Pid, 0), syscall.ESRCH)
}
