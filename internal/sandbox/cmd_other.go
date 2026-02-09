//go:build !linux

package sandbox

import "os/exec"

func applySysProcAttr(_ *exec.Cmd, _ SandboxProfile, _ Capabilities) {
	// No namespace isolation on non-Linux platforms
}
