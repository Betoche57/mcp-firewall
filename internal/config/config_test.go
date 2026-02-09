package config_test

import (
	"os"
	"strings"
	"testing"
	"time"

	"github.com/VikingOwl91/mcp-firewall/internal/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLoad_ValidMultiDownstream(t *testing.T) {
	cfg, err := config.Load("../../testdata/config/valid.yaml")
	require.NoError(t, err)

	require.Len(t, cfg.Downstreams, 2)

	echo := cfg.Downstreams["echoserver"]
	assert.Equal(t, "./testdata/echoserver/echoserver", echo.Command)
	assert.Equal(t, []string{"--verbose"}, echo.Args)
	assert.Equal(t, []string{"FOO=bar"}, echo.Env)
	assert.Equal(t, "10s", echo.Timeout)

	another := cfg.Downstreams["another"]
	assert.Equal(t, "./another-server", another.Command)
	assert.Empty(t, another.Timeout)

	assert.Equal(t, "deny", cfg.Policy.Default)
	require.Len(t, cfg.Policy.Rules, 1)
	assert.Equal(t, "allow-echo", cfg.Policy.Rules[0].Name)
	assert.Equal(t, "allow", cfg.Policy.Rules[0].Effect)

	require.Len(t, cfg.Redaction.Patterns, 1)
	assert.Equal(t, "api-key", cfg.Redaction.Patterns[0].Name)
	assert.Equal(t, `sk-[a-zA-Z0-9]{32}`, cfg.Redaction.Patterns[0].Pattern)

	assert.Equal(t, "debug", cfg.LogLevel)
	assert.Equal(t, "30s", cfg.Timeout)
	assert.Equal(t, 524288, cfg.MaxOutputBytes)
	assert.Equal(t, "30s", cfg.ApprovalTimeout)
	assert.Equal(t, 30*time.Second, cfg.ResolvedApprovalTimeout())

	assert.Equal(t, 10*time.Second, cfg.ResolvedTimeout("echoserver"))
	assert.Equal(t, 30*time.Second, cfg.ResolvedTimeout("another"))
}

func TestLoad_ValidMinimal(t *testing.T) {
	cfg, err := config.Load("../../testdata/config/valid_minimal.yaml")
	require.NoError(t, err)

	require.Len(t, cfg.Downstreams, 1)
	assert.Equal(t, "echo", cfg.Downstreams["myserver"].Command)
	assert.Equal(t, "deny", cfg.Policy.Default)
	assert.Equal(t, "info", cfg.LogLevel)
	assert.Equal(t, "60s", cfg.Timeout)
	assert.Equal(t, 1048576, cfg.MaxOutputBytes)
}

func TestLoad_FileNotFound(t *testing.T) {
	_, err := config.Load("nonexistent.yaml")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "nonexistent.yaml")
}

func TestLoad_InvalidYAML(t *testing.T) {
	_, err := config.Load("../../testdata/config/invalid.yaml")
	require.Error(t, err)
}

func TestLoad_OldFormatError(t *testing.T) {
	_, err := config.Load("../../testdata/config/old_format.yaml")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "downstreams")
}

func TestValidate_EmptyDownstreams(t *testing.T) {
	cfg := &config.Config{
		Downstreams: map[string]config.ServerConfig{},
	}
	err := cfg.Validate()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "at least one downstream")
}

func TestValidate_NilDownstreams(t *testing.T) {
	cfg := &config.Config{}
	err := cfg.Validate()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "at least one downstream")
}

func TestValidate_InvalidAlias(t *testing.T) {
	tests := []struct {
		alias string
	}{
		{"has spaces"},
		{"has.dots"},
		{"has/slashes"},
		{"has@at"},
		{""},
	}
	for _, tt := range tests {
		t.Run(tt.alias, func(t *testing.T) {
			cfg := &config.Config{
				Downstreams: map[string]config.ServerConfig{
					tt.alias: {Command: "echo"},
				},
			}
			err := cfg.Validate()
			require.Error(t, err)
			assert.Contains(t, err.Error(), "alias")
		})
	}
}

func TestValidate_AliasTooLong(t *testing.T) {
	cfg := &config.Config{
		Downstreams: map[string]config.ServerConfig{
			strings.Repeat("a", 33): {Command: "echo"},
		},
	}
	err := cfg.Validate()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "32")
}

func TestValidate_MissingDownstreamCommand(t *testing.T) {
	cfg := &config.Config{
		Downstreams: map[string]config.ServerConfig{
			"myserver": {Command: ""},
		},
	}
	err := cfg.Validate()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "command")
}

func TestValidate_InvalidPolicyDefault(t *testing.T) {
	cfg := &config.Config{
		Downstreams: map[string]config.ServerConfig{
			"myserver": {Command: "echo"},
		},
		Policy: config.PolicyConfig{Default: "maybe"},
	}
	err := cfg.Validate()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "policy default")
}

func TestValidate_InvalidPolicyEffect(t *testing.T) {
	cfg := &config.Config{
		Downstreams: map[string]config.ServerConfig{
			"myserver": {Command: "echo"},
		},
		Policy: config.PolicyConfig{
			Rules: []config.PolicyRule{
				{Name: "rule1", Expression: "true", Effect: "maybe"},
			},
		},
	}
	err := cfg.Validate()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "effect")
}

func TestValidate_DuplicateRuleNames(t *testing.T) {
	cfg := &config.Config{
		Downstreams: map[string]config.ServerConfig{
			"myserver": {Command: "echo"},
		},
		Policy: config.PolicyConfig{
			Rules: []config.PolicyRule{
				{Name: "rule1", Expression: "true", Effect: "allow"},
				{Name: "rule1", Expression: "true", Effect: "deny"},
			},
		},
	}
	err := cfg.Validate()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "duplicate")
}

func TestValidate_DefaultPolicyDefault(t *testing.T) {
	cfg := &config.Config{
		Downstreams: map[string]config.ServerConfig{
			"myserver": {Command: "echo"},
		},
	}
	err := cfg.Validate()
	require.NoError(t, err)
	assert.Equal(t, "deny", cfg.Policy.Default)
}

func TestValidate_DefaultLogLevel(t *testing.T) {
	cfg := &config.Config{
		Downstreams: map[string]config.ServerConfig{
			"myserver": {Command: "echo"},
		},
	}
	err := cfg.Validate()
	require.NoError(t, err)
	assert.Equal(t, "info", cfg.LogLevel)
}

func TestValidate_InvalidCELExpression(t *testing.T) {
	cfg := &config.Config{
		Downstreams: map[string]config.ServerConfig{
			"myserver": {Command: "echo"},
		},
		Policy: config.PolicyConfig{
			Rules: []config.PolicyRule{
				{Name: "bad", Expression: "not valid cel !!!", Effect: "allow"},
			},
		},
	}
	err := cfg.Validate()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "CEL")
}

func TestLoad_InvalidPolicy(t *testing.T) {
	_, err := config.Load("../../testdata/config/invalid_policy.yaml")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "CEL")
}

func TestValidate_DefaultTimeout(t *testing.T) {
	cfg := &config.Config{
		Downstreams: map[string]config.ServerConfig{
			"myserver": {Command: "echo"},
		},
	}
	err := cfg.Validate()
	require.NoError(t, err)
	assert.Equal(t, "60s", cfg.Timeout)
}

func TestValidate_DefaultMaxOutputBytes(t *testing.T) {
	cfg := &config.Config{
		Downstreams: map[string]config.ServerConfig{
			"myserver": {Command: "echo"},
		},
	}
	err := cfg.Validate()
	require.NoError(t, err)
	assert.Equal(t, 1048576, cfg.MaxOutputBytes)
}

func TestValidate_InvalidTimeout(t *testing.T) {
	cfg := &config.Config{
		Downstreams: map[string]config.ServerConfig{
			"myserver": {Command: "echo"},
		},
		Timeout: "not-a-duration",
	}
	err := cfg.Validate()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "timeout")
}

func TestValidate_InvalidDownstreamTimeout(t *testing.T) {
	cfg := &config.Config{
		Downstreams: map[string]config.ServerConfig{
			"myserver": {Command: "echo", Timeout: "bad"},
		},
	}
	err := cfg.Validate()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "timeout")
}

func TestValidate_PerDownstreamTimeout(t *testing.T) {
	cfg := &config.Config{
		Downstreams: map[string]config.ServerConfig{
			"fast": {Command: "echo", Timeout: "5s"},
			"slow": {Command: "echo", Timeout: "120s"},
		},
	}
	err := cfg.Validate()
	require.NoError(t, err)
	assert.Equal(t, "5s", cfg.Downstreams["fast"].Timeout)
	assert.Equal(t, "120s", cfg.Downstreams["slow"].Timeout)
}

func TestValidate_MaxOutputBytesZero(t *testing.T) {
	cfg := &config.Config{
		Downstreams: map[string]config.ServerConfig{
			"myserver": {Command: "echo"},
		},
		MaxOutputBytes: 0, // zero gets defaulted, not rejected
	}
	err := cfg.Validate()
	require.NoError(t, err)
	assert.Equal(t, 1048576, cfg.MaxOutputBytes)
}

func TestValidate_MaxOutputBytesNegative(t *testing.T) {
	cfg := &config.Config{
		Downstreams: map[string]config.ServerConfig{
			"myserver": {Command: "echo"},
		},
		MaxOutputBytes: -1,
	}
	err := cfg.Validate()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "max_output_bytes")
}

func TestResolvedTimeout_Global(t *testing.T) {
	cfg := &config.Config{
		Downstreams: map[string]config.ServerConfig{
			"myserver": {Command: "echo"},
		},
		Timeout: "30s",
	}
	require.NoError(t, cfg.Validate())

	d := cfg.ResolvedTimeout("myserver")
	assert.Equal(t, 30*time.Second, d)
}

func TestResolvedTimeout_PerDownstreamOverride(t *testing.T) {
	cfg := &config.Config{
		Downstreams: map[string]config.ServerConfig{
			"fast":   {Command: "echo", Timeout: "5s"},
			"normal": {Command: "echo"},
		},
		Timeout: "60s",
	}
	require.NoError(t, cfg.Validate())

	assert.Equal(t, 5*time.Second, cfg.ResolvedTimeout("fast"))
	assert.Equal(t, 60*time.Second, cfg.ResolvedTimeout("normal"))
}

func TestValidate_PromptEffectInRule(t *testing.T) {
	cfg := &config.Config{
		Downstreams: map[string]config.ServerConfig{
			"myserver": {Command: "echo"},
		},
		Policy: config.PolicyConfig{
			Rules: []config.PolicyRule{
				{Name: "ask-first", Expression: "true", Effect: "prompt"},
			},
		},
	}
	err := cfg.Validate()
	require.NoError(t, err)
}

func TestValidate_PromptEffectInDefault(t *testing.T) {
	cfg := &config.Config{
		Downstreams: map[string]config.ServerConfig{
			"myserver": {Command: "echo"},
		},
		Policy: config.PolicyConfig{Default: "prompt"},
	}
	err := cfg.Validate()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "policy default")
}

func TestValidate_PromptRuleWithMessage(t *testing.T) {
	cfg := &config.Config{
		Downstreams: map[string]config.ServerConfig{
			"myserver": {Command: "echo"},
		},
		Policy: config.PolicyConfig{
			Rules: []config.PolicyRule{
				{Name: "ask-first", Expression: "true", Effect: "prompt", Message: "requires approval"},
			},
		},
	}
	err := cfg.Validate()
	require.NoError(t, err)
}

func TestValidate_RedactionPatternsValid(t *testing.T) {
	cfg := &config.Config{
		Downstreams: map[string]config.ServerConfig{
			"myserver": {Command: "echo"},
		},
		Redaction: config.RedactionConfig{
			Patterns: []config.RedactionPattern{
				{Name: "api-key", Pattern: `sk-[a-zA-Z0-9]{32}`},
				{Name: "email", Pattern: `[\w.+-]+@[\w-]+\.[\w.]+`},
			},
		},
	}
	err := cfg.Validate()
	require.NoError(t, err)
}

func TestValidate_RedactionPatternsInvalidRegex(t *testing.T) {
	cfg := &config.Config{
		Downstreams: map[string]config.ServerConfig{
			"myserver": {Command: "echo"},
		},
		Redaction: config.RedactionConfig{
			Patterns: []config.RedactionPattern{
				{Name: "bad", Pattern: `[invalid`},
			},
		},
	}
	err := cfg.Validate()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "bad")
}

func TestValidate_RedactionPatternsEmpty(t *testing.T) {
	cfg := &config.Config{
		Downstreams: map[string]config.ServerConfig{
			"myserver": {Command: "echo"},
		},
	}
	err := cfg.Validate()
	require.NoError(t, err)
}

func TestValidate_RedactionPatternMissingName(t *testing.T) {
	cfg := &config.Config{
		Downstreams: map[string]config.ServerConfig{
			"myserver": {Command: "echo"},
		},
		Redaction: config.RedactionConfig{
			Patterns: []config.RedactionPattern{
				{Name: "", Pattern: `secret`},
			},
		},
	}
	err := cfg.Validate()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "name")
}

func TestValidate_RedactionPatternMissingPattern(t *testing.T) {
	cfg := &config.Config{
		Downstreams: map[string]config.ServerConfig{
			"myserver": {Command: "echo"},
		},
		Redaction: config.RedactionConfig{
			Patterns: []config.RedactionPattern{
				{Name: "empty-pat", Pattern: ""},
			},
		},
	}
	err := cfg.Validate()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "pattern")
}

func TestValidate_RedactionDuplicateNames(t *testing.T) {
	cfg := &config.Config{
		Downstreams: map[string]config.ServerConfig{
			"myserver": {Command: "echo"},
		},
		Redaction: config.RedactionConfig{
			Patterns: []config.RedactionPattern{
				{Name: "secret", Pattern: `secret`},
				{Name: "secret", Pattern: `other`},
			},
		},
	}
	err := cfg.Validate()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "duplicate")
}

func TestValidate_ApprovalTimeoutDefault(t *testing.T) {
	cfg := &config.Config{
		Downstreams: map[string]config.ServerConfig{
			"myserver": {Command: "echo"},
		},
	}
	err := cfg.Validate()
	require.NoError(t, err)
	assert.Equal(t, "2m", cfg.ApprovalTimeout)
	assert.Equal(t, 2*time.Minute, cfg.ResolvedApprovalTimeout())
}

func TestValidate_ApprovalTimeoutCustom(t *testing.T) {
	cfg := &config.Config{
		Downstreams: map[string]config.ServerConfig{
			"myserver": {Command: "echo"},
		},
		ApprovalTimeout: "30s",
	}
	err := cfg.Validate()
	require.NoError(t, err)
	assert.Equal(t, "30s", cfg.ApprovalTimeout)
	assert.Equal(t, 30*time.Second, cfg.ResolvedApprovalTimeout())
}

func TestValidate_ApprovalTimeoutInvalid(t *testing.T) {
	cfg := &config.Config{
		Downstreams: map[string]config.ServerConfig{
			"myserver": {Command: "echo"},
		},
		ApprovalTimeout: "not-a-duration",
	}
	err := cfg.Validate()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "approval_timeout")
}

func TestValidate_ValidAliases(t *testing.T) {
	tests := []string{"myserver", "my-server", "my_server", "Server1", "a", "abc-123_DEF"}
	for _, alias := range tests {
		t.Run(alias, func(t *testing.T) {
			cfg := &config.Config{
				Downstreams: map[string]config.ServerConfig{
					alias: {Command: "echo"},
				},
			}
			err := cfg.Validate()
			require.NoError(t, err)
		})
	}
}

// --- GlobalConfig tests ---

func TestGlobalConfig_BackwardCompat(t *testing.T) {
	// Existing flat config loads as default profile via LoadGlobal
	gc, err := config.LoadGlobal("../../testdata/config/valid_minimal.yaml")
	require.NoError(t, err)

	// Inline config should have the downstream
	require.Len(t, gc.Downstreams, 1)
	assert.Equal(t, "echo", gc.Downstreams["myserver"].Command)

	// No profiles defined
	assert.Empty(t, gc.Profiles)
}

func TestGlobalConfig_WithProfiles(t *testing.T) {
	gc, err := config.LoadGlobal("../../testdata/config/profiles.yaml")
	require.NoError(t, err)

	// Inline default config
	require.Len(t, gc.Downstreams, 1)
	assert.Equal(t, "./echoserver", gc.Downstreams["echoserver"].Command)
	assert.Equal(t, "deny", gc.Policy.Default)

	// Named profiles
	require.Len(t, gc.Profiles, 2)

	dev := gc.Profiles["development"]
	require.Len(t, dev.Downstreams, 1)
	assert.Equal(t, "./echoserver-dev", dev.Downstreams["echoserver"].Command)
	assert.Equal(t, "allow", dev.Policy.Default)
	assert.Equal(t, "debug", dev.LogLevel)

	strict := gc.Profiles["strict"]
	require.Len(t, strict.Downstreams, 1)
	assert.Equal(t, "deny", strict.Policy.Default)
	require.Len(t, strict.Policy.Rules, 1)
	assert.Equal(t, "prompt-all-tools", strict.Policy.Rules[0].Name)
	assert.Equal(t, "1m", strict.ApprovalTimeout)
}

func TestGlobalConfig_AllowExpansion(t *testing.T) {
	gc, err := config.LoadGlobal("../../testdata/config/profiles.yaml")
	require.NoError(t, err)
	assert.False(t, gc.AllowExpansion)
}

func TestGlobalConfig_FileNotFound(t *testing.T) {
	_, err := config.LoadGlobal("nonexistent.yaml")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "nonexistent.yaml")
}

// --- ResolveConfig pipeline tests ---

func TestResolveConfig_NoProfile_NoLocal(t *testing.T) {
	resolved, err := config.ResolveConfig("../../testdata/config/valid_minimal.yaml", "", "")
	require.NoError(t, err)
	assert.Equal(t, "echo", resolved.Config.Downstreams["myserver"].Command)
	assert.Equal(t, "deny", resolved.Config.Policy.Default)
}

func TestResolveConfig_WithProfile(t *testing.T) {
	resolved, err := config.ResolveConfig("../../testdata/config/profiles.yaml", "development", "")
	require.NoError(t, err)
	assert.Equal(t, "./echoserver-dev", resolved.Config.Downstreams["echoserver"].Command)
	assert.Equal(t, "allow", resolved.Config.Policy.Default)
	assert.Equal(t, "development", resolved.ProfileName)
}

func TestResolveConfig_WithLocal(t *testing.T) {
	resolved, err := config.ResolveConfig("../../testdata/config/valid_minimal.yaml", "", "../../testdata/config")
	require.NoError(t, err)
	// Base config is loaded
	assert.Equal(t, "echo", resolved.Config.Downstreams["myserver"].Command)
	// If a .mcp-firewall.yaml exists in the workspace, it's merged.
	// testdata/config doesn't have one, so this is a no-op.
}

func TestResolveConfig_LocalFileNotFound(t *testing.T) {
	// Missing local file is not an error — local overrides are optional
	resolved, err := config.ResolveConfig("../../testdata/config/valid_minimal.yaml", "", "/tmp/nonexistent-workspace")
	require.NoError(t, err)
	assert.Equal(t, "echo", resolved.Config.Downstreams["myserver"].Command)
}

func TestResolveConfig_ProfilePlusLocal(t *testing.T) {
	// Create a workspace dir with a .mcp-firewall.yaml for this test
	dir := t.TempDir()
	localPath := dir + "/.mcp-firewall.yaml"
	localContent := `
policy:
  rules:
    - name: block-exec
      expression: 'tool.name == "exec"'
      effect: deny
timeout: 10s
`
	require.NoError(t, writeFile(localPath, localContent))

	resolved, err := config.ResolveConfig("../../testdata/config/profiles.yaml", "development", dir)
	require.NoError(t, err)

	// Profile config applies
	assert.Equal(t, "./echoserver-dev", resolved.Config.Downstreams["echoserver"].Command)
	// Local deny rule prepended
	require.True(t, len(resolved.Config.Policy.Rules) >= 1)
	assert.Equal(t, "block-exec", resolved.Config.Policy.Rules[0].Name)
	assert.Equal(t, "local", resolved.Config.Policy.Rules[0].Source)
	// Provenance metadata
	assert.Equal(t, "development", resolved.ProfileName)
	assert.Equal(t, localPath, resolved.LocalOverride)
}

func TestResolveConfig_InvalidProfile(t *testing.T) {
	_, err := config.ResolveConfig("../../testdata/config/profiles.yaml", "nonexistent", "")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "nonexistent")
}

// --- Sandbox validation tests ---

func TestValidate_SandboxNone(t *testing.T) {
	cfg := &config.Config{
		Downstreams: map[string]config.ServerConfig{
			"myserver": {Command: "echo", Sandbox: "none"},
		},
	}
	err := cfg.Validate()
	require.NoError(t, err)
}

func TestValidate_SandboxStrict(t *testing.T) {
	cfg := &config.Config{
		Downstreams: map[string]config.ServerConfig{
			"myserver": {Command: "echo", Sandbox: "strict"},
		},
	}
	err := cfg.Validate()
	require.NoError(t, err)
}

func TestValidate_SandboxEmpty(t *testing.T) {
	cfg := &config.Config{
		Downstreams: map[string]config.ServerConfig{
			"myserver": {Command: "echo"},
		},
	}
	err := cfg.Validate()
	require.NoError(t, err)
}

func TestValidate_SandboxCustomProfile(t *testing.T) {
	cfg := &config.Config{
		Downstreams: map[string]config.ServerConfig{
			"myserver": {Command: "echo", Sandbox: "custom"},
		},
		SandboxProfiles: map[string]config.SandboxProfileConfig{
			"custom": {
				FSAllowRO: []string{"/usr", "/lib"},
				FSAllowRW: []string{"/tmp"},
				Workspace: "rw",
			},
		},
	}
	err := cfg.Validate()
	require.NoError(t, err)
}

func TestValidate_SandboxUndefinedProfile(t *testing.T) {
	cfg := &config.Config{
		Downstreams: map[string]config.ServerConfig{
			"myserver": {Command: "echo", Sandbox: "nonexistent"},
		},
	}
	err := cfg.Validate()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "nonexistent")
	assert.Contains(t, err.Error(), "not defined")
}

func TestValidate_SandboxInvalidWorkspace(t *testing.T) {
	cfg := &config.Config{
		Downstreams: map[string]config.ServerConfig{
			"myserver": {Command: "echo", Sandbox: "custom"},
		},
		SandboxProfiles: map[string]config.SandboxProfileConfig{
			"custom": {
				Workspace: "invalid",
			},
		},
	}
	err := cfg.Validate()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "workspace")
}

func TestValidate_SandboxRelativePath(t *testing.T) {
	cfg := &config.Config{
		Downstreams: map[string]config.ServerConfig{
			"myserver": {Command: "echo", Sandbox: "custom"},
		},
		SandboxProfiles: map[string]config.SandboxProfileConfig{
			"custom": {
				FSAllowRO: []string{"relative/path"},
			},
		},
	}
	err := cfg.Validate()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "absolute")
}

func TestValidate_SandboxDenyOverlapWithAllow(t *testing.T) {
	cfg := &config.Config{
		Downstreams: map[string]config.ServerConfig{
			"myserver": {Command: "echo", Sandbox: "custom"},
		},
		SandboxProfiles: map[string]config.SandboxProfileConfig{
			"custom": {
				FSDeny:    []string{"~/.ssh"},
				FSAllowRO: []string{"~/.ssh"},
			},
		},
	}
	err := cfg.Validate()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "~/.ssh")
}

func TestValidate_SandboxReservedProfileName(t *testing.T) {
	cfg := &config.Config{
		Downstreams: map[string]config.ServerConfig{
			"myserver": {Command: "echo"},
		},
		SandboxProfiles: map[string]config.SandboxProfileConfig{
			"strict": {},
		},
	}
	err := cfg.Validate()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "reserved")
}

func TestValidate_SandboxTildePaths(t *testing.T) {
	cfg := &config.Config{
		Downstreams: map[string]config.ServerConfig{
			"myserver": {Command: "echo", Sandbox: "custom"},
		},
		SandboxProfiles: map[string]config.SandboxProfileConfig{
			"custom": {
				FSDeny:    []string{"~/.ssh", "~/.gnupg"},
				FSAllowRO: []string{"/usr", "/lib"},
				FSAllowRW: []string{"/tmp"},
			},
		},
	}
	err := cfg.Validate()
	require.NoError(t, err)
}

// --- Supply chain validation tests ---

func TestValidate_HashValid(t *testing.T) {
	cfg := &config.Config{
		Downstreams: map[string]config.ServerConfig{
			"myserver": {
				Command: "echo",
				Hash:    "sha256:abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789",
			},
		},
	}
	err := cfg.Validate()
	require.NoError(t, err)
}

func TestValidate_HashInvalidFormat(t *testing.T) {
	cfg := &config.Config{
		Downstreams: map[string]config.ServerConfig{
			"myserver": {
				Command: "echo",
				Hash:    "md5:abcdef0123456789abcdef0123456789",
			},
		},
	}
	err := cfg.Validate()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported")
}

func TestValidate_HashBadHex(t *testing.T) {
	cfg := &config.Config{
		Downstreams: map[string]config.ServerConfig{
			"myserver": {
				Command: "echo",
				Hash:    "sha256:zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz",
			},
		},
	}
	err := cfg.Validate()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "hex")
}

func TestValidate_HashWrongLength(t *testing.T) {
	cfg := &config.Config{
		Downstreams: map[string]config.ServerConfig{
			"myserver": {
				Command: "echo",
				Hash:    "sha256:abcdef",
			},
		},
	}
	err := cfg.Validate()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "64")
}

func TestValidate_HashNoColon(t *testing.T) {
	cfg := &config.Config{
		Downstreams: map[string]config.ServerConfig{
			"myserver": {
				Command: "echo",
				Hash:    "nocolonhere",
			},
		},
	}
	err := cfg.Validate()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "format")
}

func TestValidate_AllowedPathsAbsolute(t *testing.T) {
	cfg := &config.Config{
		Downstreams: map[string]config.ServerConfig{
			"myserver": {Command: "echo"},
		},
		SupplyChain: config.SupplyChainConfig{
			AllowedPaths: []string{"/usr/local/bin", "/opt/servers"},
		},
	}
	err := cfg.Validate()
	require.NoError(t, err)
}

func TestValidate_AllowedPathsRelative(t *testing.T) {
	cfg := &config.Config{
		Downstreams: map[string]config.ServerConfig{
			"myserver": {Command: "echo"},
		},
		SupplyChain: config.SupplyChainConfig{
			AllowedPaths: []string{"relative/path"},
		},
	}
	err := cfg.Validate()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "absolute")
}

func TestValidate_AllowedPathsTilde(t *testing.T) {
	cfg := &config.Config{
		Downstreams: map[string]config.ServerConfig{
			"myserver": {Command: "echo"},
		},
		SupplyChain: config.SupplyChainConfig{
			AllowedPaths: []string{"~/bin"},
		},
	}
	err := cfg.Validate()
	require.NoError(t, err)
}

func TestValidate_SupplyChainEmpty(t *testing.T) {
	cfg := &config.Config{
		Downstreams: map[string]config.ServerConfig{
			"myserver": {Command: "echo"},
		},
	}
	err := cfg.Validate()
	require.NoError(t, err)
}

func TestLocalOverride_SupplyChainBlocked(t *testing.T) {
	dir := t.TempDir()
	localPath := dir + "/.mcp-firewall.yaml"
	localContent := `
supply_chain:
  allowed_paths:
    - /usr/local/bin
`
	require.NoError(t, writeFile(localPath, localContent))

	_, err := config.LoadLocal(localPath)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "supply_chain")
	assert.Contains(t, err.Error(), "not allowed")
}

func writeFile(path, content string) error {
	return os.WriteFile(path, []byte(content), 0644)
}

