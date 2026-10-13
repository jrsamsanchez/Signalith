//go:build !unix

package respond

import "os/exec"

// setProcessGroup leaves the program as exec starts it: it is stopped
// when it runs out of time.
func setProcessGroup(cmd *exec.Cmd) {}
