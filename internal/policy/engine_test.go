package policy_test

import (
	"testing"

	"github.com/VikingOwl91/mcp-firewall/internal/config"
	"github.com/VikingOwl91/mcp-firewall/internal/policy"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNew_ValidRules(t *testing.T) {
	cfg := config.PolicyConfig{
		Default: "deny",
		Rules: []config.PolicyRule{
			{Name: "allow-echo", Expression: `server == "echoserver"`, Effect: "allow"},
		},
	}
	e, err := policy.New(cfg)
	require.NoError(t, err)
	assert.NotNil(t, e)
}

func TestNew_InvalidExpression(t *testing.T) {
	cfg := config.PolicyConfig{
		Default: "deny",
		Rules: []config.PolicyRule{
			{Name: "bad", Expression: `this is not valid CEL !!!`, Effect: "allow"},
		},
	}
	_, err := policy.New(cfg)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "bad")
}

func TestEvaluate_AllowByRule(t *testing.T) {
	cfg := config.PolicyConfig{
		Default: "deny",
		Rules: []config.PolicyRule{
			{Name: "allow-echo", Expression: `server == "echoserver" && tool.name == "echo"`, Effect: "allow"},
		},
	}
	e, err := policy.New(cfg)
	require.NoError(t, err)

	effect, rule := e.Evaluate(policy.RequestContext{
		Method: "tools/call",
		Server: "echoserver",
		Tool:   policy.ToolContext{Name: "echo"},
	})
	assert.Equal(t, policy.Allow, effect)
	assert.Equal(t, "allow-echo", rule)
}

func TestEvaluate_DenyByRule(t *testing.T) {
	cfg := config.PolicyConfig{
		Default: "allow",
		Rules: []config.PolicyRule{
			{Name: "block-danger", Expression: `tool.name == "danger"`, Effect: "deny"},
		},
	}
	e, err := policy.New(cfg)
	require.NoError(t, err)

	effect, rule := e.Evaluate(policy.RequestContext{
		Method: "tools/call",
		Server: "myserver",
		Tool:   policy.ToolContext{Name: "danger"},
	})
	assert.Equal(t, policy.Deny, effect)
	assert.Equal(t, "block-danger", rule)
}

func TestEvaluate_DefaultDeny(t *testing.T) {
	cfg := config.PolicyConfig{
		Default: "deny",
		Rules: []config.PolicyRule{
			{Name: "allow-specific", Expression: `tool.name == "safe"`, Effect: "allow"},
		},
	}
	e, err := policy.New(cfg)
	require.NoError(t, err)

	effect, rule := e.Evaluate(policy.RequestContext{
		Method: "tools/call",
		Server: "myserver",
		Tool:   policy.ToolContext{Name: "other"},
	})
	assert.Equal(t, policy.Deny, effect)
	assert.Equal(t, "default:deny", rule)
}

func TestEvaluate_DefaultAllow(t *testing.T) {
	cfg := config.PolicyConfig{
		Default: "allow",
		Rules:   []config.PolicyRule{},
	}
	e, err := policy.New(cfg)
	require.NoError(t, err)

	effect, rule := e.Evaluate(policy.RequestContext{
		Method: "tools/call",
		Server: "myserver",
		Tool:   policy.ToolContext{Name: "anything"},
	})
	assert.Equal(t, policy.Allow, effect)
	assert.Equal(t, "default:allow", rule)
}

func TestEvaluate_FirstMatchWins(t *testing.T) {
	cfg := config.PolicyConfig{
		Default: "deny",
		Rules: []config.PolicyRule{
			{Name: "deny-all", Expression: `true`, Effect: "deny"},
			{Name: "allow-all", Expression: `true`, Effect: "allow"},
		},
	}
	e, err := policy.New(cfg)
	require.NoError(t, err)

	effect, rule := e.Evaluate(policy.RequestContext{
		Method: "tools/call",
		Server: "myserver",
		Tool:   policy.ToolContext{Name: "test"},
	})
	assert.Equal(t, policy.Deny, effect)
	assert.Equal(t, "deny-all", rule)
}

func TestEvaluate_ToolArguments(t *testing.T) {
	cfg := config.PolicyConfig{
		Default: "deny",
		Rules: []config.PolicyRule{
			{Name: "allow-safe-args", Expression: `tool.arguments["mode"] == "safe"`, Effect: "allow"},
		},
	}
	e, err := policy.New(cfg)
	require.NoError(t, err)

	effect, rule := e.Evaluate(policy.RequestContext{
		Method: "tools/call",
		Server: "myserver",
		Tool: policy.ToolContext{
			Name:      "run",
			Arguments: map[string]any{"mode": "safe"},
		},
	})
	assert.Equal(t, policy.Allow, effect)
	assert.Equal(t, "allow-safe-args", rule)
}

func TestEvaluate_ResourceURI(t *testing.T) {
	cfg := config.PolicyConfig{
		Default: "allow",
		Rules: []config.PolicyRule{
			{Name: "block-etc", Expression: `resource.uri.startsWith("file:///etc/")`, Effect: "deny"},
		},
	}
	e, err := policy.New(cfg)
	require.NoError(t, err)

	effect, rule := e.Evaluate(policy.RequestContext{
		Method:   "resources/read",
		Server:   "files",
		Resource: policy.ResourceContext{URI: "file:///etc/passwd"},
	})
	assert.Equal(t, policy.Deny, effect)
	assert.Equal(t, "block-etc", rule)

	effect, rule = e.Evaluate(policy.RequestContext{
		Method:   "resources/read",
		Server:   "files",
		Resource: policy.ResourceContext{URI: "file:///home/user/data"},
	})
	assert.Equal(t, policy.Allow, effect)
	assert.Equal(t, "default:allow", rule)
}

func TestEvaluate_FailClosed(t *testing.T) {
	// A rule that evaluates to a non-boolean should fail closed (deny)
	cfg := config.PolicyConfig{
		Default: "allow",
		Rules: []config.PolicyRule{
			{Name: "bad-rule", Expression: `"not a bool"`, Effect: "allow"},
		},
	}
	e, err := policy.New(cfg)
	require.NoError(t, err)

	effect, rule := e.Evaluate(policy.RequestContext{
		Method: "tools/call",
		Server: "myserver",
		Tool:   policy.ToolContext{Name: "test"},
	})
	assert.Equal(t, policy.Deny, effect)
	assert.Contains(t, rule, "error")
}

func TestEvaluate_MethodMatching(t *testing.T) {
	cfg := config.PolicyConfig{
		Default: "deny",
		Rules: []config.PolicyRule{
			{Name: "allow-list", Expression: `method == "tools/list"`, Effect: "allow"},
		},
	}
	e, err := policy.New(cfg)
	require.NoError(t, err)

	effect, _ := e.Evaluate(policy.RequestContext{
		Method: "tools/list",
		Server: "myserver",
	})
	assert.Equal(t, policy.Allow, effect)

	effect, _ = e.Evaluate(policy.RequestContext{
		Method: "tools/call",
		Server: "myserver",
	})
	assert.Equal(t, policy.Deny, effect)
}
