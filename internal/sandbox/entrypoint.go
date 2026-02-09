package sandbox

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
)

// RunSandboxEntrypoint is called when the __sandbox__ sentinel is detected.
// It reads config from env, applies Landlock, filters env, and exec's the
// real downstream command. On success, it does not return (syscall.Exec
// replaces the process). On non-Linux, it falls back to os/exec.
func RunSandboxEntrypoint() error {
	configJSON := os.Getenv("_MCP_SANDBOX_CONFIG")
	if configJSON == "" {
		return fmt.Errorf("_MCP_SANDBOX_CONFIG environment variable not set")
	}

	var cfg SandboxExecConfig
	if err := json.Unmarshal([]byte(configJSON), &cfg); err != nil {
		return fmt.Errorf("parsing _MCP_SANDBOX_CONFIG: %w", err)
	}

	// Build filtered env from original env + allowlist
	filteredEnv := FilterEnv(cfg.Env, cfg.EnvAllowlist)

	// Apply Landlock if available (Linux only, no-op on other platforms)
	if err := ApplyLandlock(cfg); err != nil && err != ErrLandlockUnsupported {
		return fmt.Errorf("applying Landlock: %w", err)
	}

	// Resolve command path using the filtered env's PATH
	resolvedPath, err := lookPathWithEnv(cfg.Command, filteredEnv)
	if err != nil {
		return fmt.Errorf("resolving command %q: %w", cfg.Command, err)
	}

	// Replace process with the downstream command
	return execCommand(resolvedPath, cfg.Args, filteredEnv)
}

// lookPathWithEnv resolves a command using the PATH from the given env slice.
func lookPathWithEnv(command string, env []string) (string, error) {
	// If the command is already an absolute path, use it directly
	if len(command) > 0 && command[0] == '/' {
		if _, err := os.Stat(command); err != nil {
			return "", fmt.Errorf("resolving command %q: %w", command, err)
		}
		return command, nil
	}

	// Extract PATH from env
	for _, e := range env {
		if len(e) > 5 && e[:5] == "PATH=" {
			os.Setenv("PATH", e[5:])
			break
		}
	}

	return exec.LookPath(command)
}
