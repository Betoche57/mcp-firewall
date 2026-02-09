package sandbox

import (
	"context"
	"encoding/json"
	"runtime"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestBuildSandboxedCmd_ArgsFormat(t *testing.T) {
	cmd, err := BuildSandboxedCmd(
		context.Background(),
		"/usr/bin/mcp-firewall",
		StrictProfile(),
		Capabilities{Landlock: true, LandlockABI: 5},
		"/usr/bin/echo", []string{"hello"}, []string{"PATH=/usr/bin"}, "/workspace",
	)
	require.NoError(t, err)

	// args should be [self, "__sandbox__", "--", cmd, args...]
	assert.Equal(t, "/usr/bin/mcp-firewall", cmd.Path)
	assert.Equal(t, []string{"/usr/bin/mcp-firewall", "__sandbox__", "--", "/usr/bin/echo", "hello"}, cmd.Args)
}

func TestBuildSandboxedCmd_EnvOnlyConfig(t *testing.T) {
	cmd, err := BuildSandboxedCmd(
		context.Background(),
		"/usr/bin/mcp-firewall",
		StrictProfile(),
		Capabilities{Landlock: true, LandlockABI: 5},
		"/usr/bin/echo", nil, []string{"PATH=/usr/bin", "SECRET=x"}, "",
	)
	require.NoError(t, err)

	// cmd.Env should contain only _MCP_SANDBOX_CONFIG
	require.Len(t, cmd.Env, 1)
	assert.True(t, strings.HasPrefix(cmd.Env[0], "_MCP_SANDBOX_CONFIG="))
}

func TestBuildSandboxedCmd_ConfigJSON(t *testing.T) {
	cmd, err := BuildSandboxedCmd(
		context.Background(),
		"/usr/bin/mcp-firewall",
		StrictProfile(),
		Capabilities{Landlock: true, LandlockABI: 5},
		"/usr/bin/echo", []string{"world"}, []string{"PATH=/usr/bin"}, "/workspace",
	)
	require.NoError(t, err)

	configJSON := strings.TrimPrefix(cmd.Env[0], "_MCP_SANDBOX_CONFIG=")
	var cfg SandboxExecConfig
	require.NoError(t, json.Unmarshal([]byte(configJSON), &cfg))

	assert.False(t, cfg.Network)
	assert.Equal(t, "/usr/bin/echo", cfg.Command)
	assert.Equal(t, []string{"world"}, cfg.Args)
	assert.Equal(t, []string{"PATH=/usr/bin"}, cfg.Env)
	assert.Contains(t, cfg.EnvAllowlist, "PATH")
	assert.Contains(t, cfg.FSDeny, "~/.ssh")
	assert.Equal(t, "/workspace", cfg.Workspace)
	assert.False(t, cfg.WorkspaceRW)
}

func TestBuildSandboxedCmd_WorkspaceInConfig(t *testing.T) {
	profile := StrictProfile()
	profile.Workspace = "rw"

	cmd, err := BuildSandboxedCmd(
		context.Background(),
		"/usr/bin/mcp-firewall",
		profile,
		Capabilities{Landlock: true, LandlockABI: 5},
		"/usr/bin/echo", nil, nil, "/my/workspace",
	)
	require.NoError(t, err)

	configJSON := strings.TrimPrefix(cmd.Env[0], "_MCP_SANDBOX_CONFIG=")
	var cfg SandboxExecConfig
	require.NoError(t, json.Unmarshal([]byte(configJSON), &cfg))
	assert.Equal(t, "/my/workspace", cfg.Workspace)
	assert.True(t, cfg.WorkspaceRW)
}

func TestBuildSandboxedCmd_NetworkAllowed(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("clone flags only on Linux")
	}

	profile := StrictProfile()
	profile.Network = true

	cmd, err := BuildSandboxedCmd(
		context.Background(),
		"/usr/bin/mcp-firewall",
		profile,
		Capabilities{UserNamespace: true, Landlock: true, LandlockABI: 5},
		"/usr/bin/echo", nil, nil, "",
	)
	require.NoError(t, err)

	// No CLONE_NEWNET when network is allowed
	if cmd.SysProcAttr != nil {
		assert.Zero(t, cmd.SysProcAttr.Cloneflags)
	}
}

func TestBuildSandboxedCmd_StrictFull(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("clone flags only on Linux")
	}

	cmd, err := BuildSandboxedCmd(
		context.Background(),
		"/usr/bin/mcp-firewall",
		StrictProfile(),
		Capabilities{UserNamespace: true, Landlock: true, LandlockABI: 5},
		"/usr/bin/echo", nil, nil, "",
	)
	require.NoError(t, err)

	// Full caps + no network → should have clone flags
	require.NotNil(t, cmd.SysProcAttr)
	assert.NotZero(t, cmd.SysProcAttr.Cloneflags)
}

func TestBuildSandboxedCmd_StrictNoNamespace(t *testing.T) {
	cmd, err := BuildSandboxedCmd(
		context.Background(),
		"/usr/bin/mcp-firewall",
		StrictProfile(),
		Capabilities{UserNamespace: false, Landlock: true, LandlockABI: 5},
		"/usr/bin/echo", nil, nil, "",
	)
	require.NoError(t, err)

	// No namespace caps → no clone flags (or nil SysProcAttr)
	if cmd.SysProcAttr != nil {
		assert.Zero(t, cmd.SysProcAttr.Cloneflags)
	}
}

func TestBuildSandboxedCmd_StrictNoCaps(t *testing.T) {
	// strict profile + no Landlock → error
	_, err := BuildSandboxedCmd(
		context.Background(),
		"/usr/bin/mcp-firewall",
		StrictProfile(),
		Capabilities{UserNamespace: false, Landlock: false},
		"/usr/bin/echo", nil, nil, "",
	)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "strict")
}

func TestBuildSandboxedCmd_CustomNoLandlock(t *testing.T) {
	// Non-strict profile with no Landlock → allowed (env filter only)
	profile := SandboxProfile{
		Name:         "custom",
		EnvAllowlist: []string{"PATH"},
		Workspace:    "ro",
	}

	cmd, err := BuildSandboxedCmd(
		context.Background(),
		"/usr/bin/mcp-firewall",
		profile,
		Capabilities{UserNamespace: false, Landlock: false},
		"/usr/bin/echo", nil, nil, "",
	)
	require.NoError(t, err)
	assert.NotNil(t, cmd)
}
