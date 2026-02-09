//go:build linux

package sandbox

import "syscall"

// execCommand replaces the current process with the given command.
func execCommand(resolvedPath string, args []string, env []string) error {
	argv := make([]string, 0, 1+len(args))
	argv = append(argv, resolvedPath)
	argv = append(argv, args...)
	return syscall.Exec(resolvedPath, argv, env)
}
