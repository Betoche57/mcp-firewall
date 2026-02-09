//go:build linux

package sandbox

import (
	"os"
	"os/exec"
	"syscall"
)

func applySysProcAttr(cmd *exec.Cmd, profile SandboxProfile, caps Capabilities) {
	if !caps.UserNamespace || profile.Network {
		return
	}

	uid := os.Getuid()
	gid := os.Getgid()

	cmd.SysProcAttr = &syscall.SysProcAttr{
		Cloneflags: syscall.CLONE_NEWUSER | syscall.CLONE_NEWNET,
		UidMappings: []syscall.SysProcIDMap{
			{ContainerID: 0, HostID: uid, Size: 1},
		},
		GidMappings: []syscall.SysProcIDMap{
			{ContainerID: 0, HostID: gid, Size: 1},
		},
	}
}
