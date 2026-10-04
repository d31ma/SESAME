//go:build !unix

package sesame

import "os/exec"

func ownProcessGroup(command *exec.Cmd) {}

func killProcessGroup(command *exec.Cmd) {
	_ = command.Process.Kill()
}

func processGroupEnded(command *exec.Cmd) bool {
	return true
}
