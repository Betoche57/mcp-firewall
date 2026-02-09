package policy

import (
	"fmt"

	"github.com/VikingOwl91/mcp-firewall/internal/config"
	"github.com/google/cel-go/cel"
)

type Effect string

const (
	Allow Effect = "allow"
	Deny  Effect = "deny"
)

type RequestContext struct {
	Method   string
	Server   string
	Tool     ToolContext
	Resource ResourceContext
}

type ToolContext struct {
	Name      string
	Arguments map[string]any
}

type ResourceContext struct {
	URI string
}

type compiledRule struct {
	name    string
	program cel.Program
	effect  Effect
}

type Engine struct {
	defaultEffect Effect
	rules         []compiledRule
}

func New(cfg config.PolicyConfig) (*Engine, error) {
	env, err := cel.NewEnv(
		cel.Variable("method", cel.StringType),
		cel.Variable("server", cel.StringType),
		cel.Variable("tool", cel.MapType(cel.StringType, cel.DynType)),
		cel.Variable("resource", cel.MapType(cel.StringType, cel.DynType)),
	)
	if err != nil {
		return nil, fmt.Errorf("creating CEL environment: %w", err)
	}

	rules := make([]compiledRule, 0, len(cfg.Rules))
	for _, r := range cfg.Rules {
		ast, issues := env.Compile(r.Expression)
		if issues != nil && issues.Err() != nil {
			return nil, fmt.Errorf("compiling rule %q: %w", r.Name, issues.Err())
		}

		prg, err := env.Program(ast)
		if err != nil {
			return nil, fmt.Errorf("programming rule %q: %w", r.Name, err)
		}

		rules = append(rules, compiledRule{
			name:    r.Name,
			program: prg,
			effect:  Effect(r.Effect),
		})
	}

	return &Engine{
		defaultEffect: Effect(cfg.Default),
		rules:         rules,
	}, nil
}

func (e *Engine) Evaluate(rc RequestContext) (Effect, string) {
	activation := map[string]any{
		"method": rc.Method,
		"server": rc.Server,
		"tool": map[string]any{
			"name":      rc.Tool.Name,
			"arguments": ensureMap(rc.Tool.Arguments),
		},
		"resource": map[string]any{
			"uri": rc.Resource.URI,
		},
	}

	for _, rule := range e.rules {
		out, _, err := rule.program.Eval(activation)
		if err != nil {
			return Deny, fmt.Sprintf("error evaluating rule %q: %v", rule.name, err)
		}

		matched, ok := out.Value().(bool)
		if !ok {
			return Deny, fmt.Sprintf("error evaluating rule %q: non-boolean result", rule.name)
		}

		if matched {
			return rule.effect, rule.name
		}
	}

	return e.defaultEffect, fmt.Sprintf("default:%s", e.defaultEffect)
}

func ensureMap(m map[string]any) map[string]any {
	if m == nil {
		return map[string]any{}
	}
	return m
}
