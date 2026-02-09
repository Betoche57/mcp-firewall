package sandbox

import (
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
)

// SandboxExecConfig is the JSON payload passed via _MCP_SANDBOX_CONFIG env var.
type SandboxExecConfig struct {
	Network      bool     `json:"network"`
	EnvAllowlist []string `json:"env_allowlist"`
	Env          []string `json:"env"`
	FSDeny       []string `json:"fs_deny"`
	FSAllowRO    []string `json:"fs_allow_ro"`
	FSAllowRW    []string `json:"fs_allow_rw"`
	Workspace    string   `json:"workspace,omitempty"`
	WorkspaceRW  bool     `json:"workspace_rw"`
	Command      string   `json:"command"`
	Args         []string `json:"args"`
}

// BuildSandboxedCmd transforms a downstream spawn into a sandboxed re-exec.
// selfPath is the path to the current mcp-firewall binary.
func BuildSandboxedCmd(
	ctx context.Context,
	selfPath string,
	profile SandboxProfile,
	caps Capabilities,
	command string, args, env []string,
	workspace string,
) (*exec.Cmd, error) {
	// strict profile requires at least Landlock
	if profile.Name == "strict" && !caps.Landlock {
		return nil, fmt.Errorf("sandbox profile %q requires Landlock support, but it is not available", profile.Name)
	}

	// Build exec args: [self, "__sandbox__", "--", cmd, args...]
	execArgs := make([]string, 0, 3+len(args))
	execArgs = append(execArgs, "__sandbox__", "--", command)
	execArgs = append(execArgs, args...)

	cmd := exec.CommandContext(ctx, selfPath, execArgs...)

	// Build config payload
	cfg := SandboxExecConfig{
		Network:      profile.Network,
		EnvAllowlist: profile.EnvAllowlist,
		Env:          env,
		FSDeny:       profile.FSDeny,
		FSAllowRO:    profile.FSAllowRO,
		FSAllowRW:    profile.FSAllowRW,
		Workspace:    workspace,
		WorkspaceRW:  profile.Workspace == "rw",
		Command:      command,
		Args:         args,
	}

	configJSON, err := json.Marshal(cfg)
	if err != nil {
		return nil, fmt.Errorf("marshaling sandbox config: %w", err)
	}

	// Only pass the config env var — the re-exec process handles the rest
	cmd.Env = []string{"_MCP_SANDBOX_CONFIG=" + string(configJSON)}

	// Apply namespace isolation if available and needed
	applySysProcAttr(cmd, profile, caps)

	return cmd, nil
}
