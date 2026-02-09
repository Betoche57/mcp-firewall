package supply

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// ResolvePath resolves a command to an absolute path.
// Uses exec.LookPath for non-absolute commands, then evaluates symlinks.
func ResolvePath(command string) (string, error) {
	var absPath string

	if filepath.IsAbs(command) {
		absPath = command
	} else {
		found, err := exec.LookPath(command)
		if err != nil {
			return "", fmt.Errorf("resolving command %q: %w", command, err)
		}
		abs, err := filepath.Abs(found)
		if err != nil {
			return "", fmt.Errorf("absolute path for %q: %w", found, err)
		}
		absPath = abs
	}

	resolved, err := filepath.EvalSymlinks(absPath)
	if err != nil {
		return "", fmt.Errorf("resolving symlinks for %q: %w", absPath, err)
	}

	return resolved, nil
}

// ValidatePath checks the resolved path is under one of the allowed prefixes.
// Empty allowedPaths means no restriction (backward compat).
func ValidatePath(resolved string, allowedPaths []string) error {
	if len(allowedPaths) == 0 {
		return nil
	}

	for _, allowed := range allowedPaths {
		prefix := expandTilde(allowed)

		// Ensure prefix ends with separator for proper directory matching
		dir := prefix
		if !strings.HasSuffix(dir, string(filepath.Separator)) {
			dir += string(filepath.Separator)
		}

		// Check if resolved path is under the allowed directory,
		// or is exactly the allowed directory
		if resolved == prefix || strings.HasPrefix(resolved, dir) {
			return nil
		}
	}

	return fmt.Errorf("command path %q is not under any allowed path", resolved)
}

func expandTilde(path string) string {
	if strings.HasPrefix(path, "~/") {
		if home, err := os.UserHomeDir(); err == nil {
			return filepath.Join(home, path[2:])
		}
	}
	return path
}
