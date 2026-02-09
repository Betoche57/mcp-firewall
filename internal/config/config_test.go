package config_test

import (
	"strings"
	"testing"

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

	another := cfg.Downstreams["another"]
	assert.Equal(t, "./another-server", another.Command)

	assert.Equal(t, "deny", cfg.Policy.Default)
	require.Len(t, cfg.Policy.Rules, 1)
	assert.Equal(t, "allow-echo", cfg.Policy.Rules[0].Name)
	assert.Equal(t, "allow", cfg.Policy.Rules[0].Effect)

	assert.Equal(t, "debug", cfg.LogLevel)
}

func TestLoad_ValidMinimal(t *testing.T) {
	cfg, err := config.Load("../../testdata/config/valid_minimal.yaml")
	require.NoError(t, err)

	require.Len(t, cfg.Downstreams, 1)
	assert.Equal(t, "echo", cfg.Downstreams["myserver"].Command)
	assert.Equal(t, "deny", cfg.Policy.Default)
	assert.Equal(t, "info", cfg.LogLevel)
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
