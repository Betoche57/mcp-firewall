package sandbox

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRunSandboxEntrypoint_MissingConfig(t *testing.T) {
	os.Unsetenv("_MCP_SANDBOX_CONFIG")
	err := RunSandboxEntrypoint()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "_MCP_SANDBOX_CONFIG")
}

func TestRunSandboxEntrypoint_InvalidJSON(t *testing.T) {
	t.Setenv("_MCP_SANDBOX_CONFIG", "not-json")
	err := RunSandboxEntrypoint()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "parsing")
}

func TestRunSandboxEntrypoint_CommandNotFound(t *testing.T) {
	// Include FS allow paths so Landlock doesn't fail on empty ruleset
	t.Setenv("_MCP_SANDBOX_CONFIG", `{"command":"__nonexistent_cmd_12345","args":[],"env":["PATH=/usr/bin"],"env_allowlist":["PATH"],"fs_allow_ro":["/usr","/bin","/lib","/lib64","/sbin"],"fs_allow_rw":["/tmp"]}`)
	err := RunSandboxEntrypoint()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "resolving command")
}
