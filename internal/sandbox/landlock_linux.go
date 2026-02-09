//go:build linux

package sandbox

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"
)

// Landlock access rights for filesystem operations (ABI v1+).
const (
	llAccessFSRead uint64 = unix.LANDLOCK_ACCESS_FS_EXECUTE |
		unix.LANDLOCK_ACCESS_FS_READ_FILE |
		unix.LANDLOCK_ACCESS_FS_READ_DIR

	llAccessFSWrite uint64 = unix.LANDLOCK_ACCESS_FS_WRITE_FILE |
		unix.LANDLOCK_ACCESS_FS_REMOVE_DIR |
		unix.LANDLOCK_ACCESS_FS_REMOVE_FILE |
		unix.LANDLOCK_ACCESS_FS_MAKE_CHAR |
		unix.LANDLOCK_ACCESS_FS_MAKE_DIR |
		unix.LANDLOCK_ACCESS_FS_MAKE_REG |
		unix.LANDLOCK_ACCESS_FS_MAKE_SOCK |
		unix.LANDLOCK_ACCESS_FS_MAKE_FIFO |
		unix.LANDLOCK_ACCESS_FS_MAKE_BLOCK |
		unix.LANDLOCK_ACCESS_FS_MAKE_SYM

	llAccessFSAll uint64 = llAccessFSRead | llAccessFSWrite
)

// ApplyLandlock restricts the current process's filesystem access.
// This is an allowlist model: anything not explicitly allowed is denied.
func ApplyLandlock(cfg SandboxExecConfig) error {
	abi := detectLandlockABI()
	if abi <= 0 {
		return ErrLandlockUnsupported
	}

	// Determine handled access rights based on ABI version
	handledAccess := llAccessFSAll
	if abi >= 2 {
		handledAccess |= unix.LANDLOCK_ACCESS_FS_REFER
	}
	if abi >= 3 {
		handledAccess |= unix.LANDLOCK_ACCESS_FS_TRUNCATE
	}

	// Create ruleset
	attr := unix.LandlockRulesetAttr{
		Access_fs: handledAccess,
	}
	rulesetFD, _, errno := syscall.Syscall(
		unix.SYS_LANDLOCK_CREATE_RULESET,
		uintptr(unsafe.Pointer(&attr)),
		unsafe.Sizeof(attr),
		0,
	)
	if errno != 0 {
		return fmt.Errorf("landlock_create_ruleset: %w", errno)
	}
	defer syscall.Close(int(rulesetFD))

	home, _ := os.UserHomeDir()

	// Add read-only path rules
	for _, path := range cfg.FSAllowRO {
		path = expandTilde(path, home)
		if err := landlockAddPathRule(int(rulesetFD), path, llAccessFSRead&handledAccess); err != nil {
			if !os.IsNotExist(err) && !isENOENT(err) {
				return fmt.Errorf("landlock add RO rule %q: %w", path, err)
			}
		}
	}

	// Add read-write path rules
	for _, path := range cfg.FSAllowRW {
		path = expandTilde(path, home)
		if err := landlockAddPathRule(int(rulesetFD), path, handledAccess); err != nil {
			if !os.IsNotExist(err) && !isENOENT(err) {
				return fmt.Errorf("landlock add RW rule %q: %w", path, err)
			}
		}
	}

	// Add workspace path if set
	if cfg.Workspace != "" {
		ws := expandTilde(cfg.Workspace, home)
		access := llAccessFSRead & handledAccess
		if cfg.WorkspaceRW {
			access = handledAccess
		}
		if err := landlockAddPathRule(int(rulesetFD), ws, access); err != nil {
			if !os.IsNotExist(err) && !isENOENT(err) {
				return fmt.Errorf("landlock add workspace rule %q: %w", ws, err)
			}
		}
	}

	// Set no_new_privs — required by Landlock
	if err := unix.Prctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0); err != nil {
		return fmt.Errorf("prctl(PR_SET_NO_NEW_PRIVS): %w", err)
	}

	// Restrict self
	_, _, errno = syscall.Syscall(
		unix.SYS_LANDLOCK_RESTRICT_SELF,
		rulesetFD,
		0,
		0,
	)
	if errno != 0 {
		return fmt.Errorf("landlock_restrict_self: %w", errno)
	}

	return nil
}

func landlockAddPathRule(rulesetFD int, path string, access uint64) error {
	if access == 0 {
		return nil
	}

	fd, err := syscall.Open(path, unix.O_PATH|syscall.O_CLOEXEC, 0)
	if err != nil {
		return err
	}
	defer syscall.Close(fd)

	pathBeneath := unix.LandlockPathBeneathAttr{
		Allowed_access: access,
		Parent_fd:      int32(fd),
	}

	_, _, errno := syscall.Syscall6(
		unix.SYS_LANDLOCK_ADD_RULE,
		uintptr(rulesetFD),
		1, // LANDLOCK_RULE_PATH_BENEATH
		uintptr(unsafe.Pointer(&pathBeneath)),
		0,
		0,
		0,
	)
	if errno != 0 {
		return errno
	}
	return nil
}

func expandTilde(path, home string) string {
	if strings.HasPrefix(path, "~/") {
		return filepath.Join(home, path[2:])
	}
	return path
}

func isENOENT(err error) bool {
	return err == syscall.ENOENT
}
