//go:build linux

package sandbox

import (
	"os"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"
)

// DetectCapabilities probes the host for sandbox capabilities.
func DetectCapabilities() Capabilities {
	abi := detectLandlockABI()
	return Capabilities{
		UserNamespace: detectUserNamespace(),
		Landlock:      abi > 0,
		LandlockABI:   abi,
	}
}

func detectUserNamespace() bool {
	// Check /proc/sys/kernel/unprivileged_userns_clone if it exists
	data, err := os.ReadFile("/proc/sys/kernel/unprivileged_userns_clone")
	if err == nil {
		return strings.TrimSpace(string(data)) == "1"
	}

	// File doesn't exist — try a short-lived unshare.
	// If the kernel doesn't have the sysctl, namespaces might still work.
	r1, _, errno := syscall.RawSyscall(syscall.SYS_UNSHARE, syscall.CLONE_NEWUSER, 0, 0)
	if errno == 0 && r1 == 0 {
		return true
	}
	return false
}

func detectLandlockABI() int {
	// landlock_create_ruleset(NULL, 0, LANDLOCK_CREATE_RULESET_VERSION)
	// returns the highest ABI version supported by the kernel.
	abi, _, errno := syscall.Syscall(
		unix.SYS_LANDLOCK_CREATE_RULESET,
		0, // attr = NULL
		0, // size = 0
		uintptr(unix.LANDLOCK_CREATE_RULESET_VERSION),
	)
	if errno != 0 {
		return 0
	}
	return int(abi)
}

