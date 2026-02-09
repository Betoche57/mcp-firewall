package config

import (
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/google/cel-go/cel"
	"gopkg.in/yaml.v3"
)

// LocalOverride represents a .mcp-firewall.yaml in a workspace directory.
type LocalOverride struct {
	Policy          *PolicyConfig    `yaml:"policy,omitempty" json:"policy,omitempty"`
	Redaction       *RedactionConfig `yaml:"redaction,omitempty" json:"redaction,omitempty"`
	Timeout         string           `yaml:"timeout,omitempty" json:"timeout,omitempty"`
	ApprovalTimeout string           `yaml:"approval_timeout,omitempty" json:"approval_timeout,omitempty"`
	MaxOutputBytes  *int             `yaml:"max_output_bytes,omitempty" json:"max_output_bytes,omitempty"`
	LogLevel        string           `yaml:"log_level,omitempty" json:"log_level,omitempty"`
}

// localOverrideRaw is used to detect forbidden fields in local overrides.
type localOverrideRaw struct {
	Downstreams any `yaml:"downstreams" json:"downstreams"`
	Profiles    any `yaml:"profiles" json:"profiles"`
	SupplyChain any `yaml:"supply_chain" json:"supply_chain"`
}

// LoadLocal loads a local override file (.mcp-firewall.yaml, .yml, or .json).
func LoadLocal(path string) (*LocalOverride, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading local override %s: %w", path, err)
	}

	isJSON := strings.HasSuffix(path, ".json")

	// Check for forbidden fields
	var raw localOverrideRaw
	if isJSON {
		_ = json.Unmarshal(data, &raw)
	} else {
		_ = yaml.Unmarshal(data, &raw)
	}
	if raw.Downstreams != nil {
		return nil, fmt.Errorf("local override %s: 'downstreams' is not allowed in local overrides", path)
	}
	if raw.Profiles != nil {
		return nil, fmt.Errorf("local override %s: 'profiles' is not allowed in local overrides", path)
	}
	if raw.SupplyChain != nil {
		return nil, fmt.Errorf("local override %s: 'supply_chain' is not allowed in local overrides", path)
	}

	var lo LocalOverride
	if isJSON {
		if err := json.Unmarshal(data, &lo); err != nil {
			return nil, fmt.Errorf("parsing local override %s: %w", path, err)
		}
	} else {
		if err := yaml.Unmarshal(data, &lo); err != nil {
			return nil, fmt.Errorf("parsing local override %s: %w", path, err)
		}
	}

	if err := lo.validate(path); err != nil {
		return nil, err
	}

	return &lo, nil
}

func (lo *LocalOverride) validate(path string) error {
	if lo.Policy != nil {
		if lo.Policy.Default != "" {
			return fmt.Errorf("local override %s: 'policy.default' is not allowed in local overrides", path)
		}
		seen := make(map[string]bool)
		for i, rule := range lo.Policy.Rules {
			if rule.Effect != "allow" && rule.Effect != "deny" && rule.Effect != "prompt" {
				return fmt.Errorf("local override %s: rule %d (%q): effect must be 'allow', 'deny', or 'prompt', got %q", path, i, rule.Name, rule.Effect)
			}
			if rule.Name == "" {
				return fmt.Errorf("local override %s: rule %d: name is required", path, i)
			}
			if seen[rule.Name] {
				return fmt.Errorf("local override %s: rule %d: duplicate rule name %q", path, i, rule.Name)
			}
			seen[rule.Name] = true
		}
		if err := validateLocalCEL(lo.Policy.Rules); err != nil {
			return fmt.Errorf("local override %s: %w", path, err)
		}
	}

	if lo.Redaction != nil {
		seen := make(map[string]bool)
		for i, p := range lo.Redaction.Patterns {
			if p.Name == "" {
				return fmt.Errorf("local override %s: redaction pattern %d: name is required", path, i)
			}
			if p.Pattern == "" {
				return fmt.Errorf("local override %s: redaction pattern %q: pattern is required", path, p.Name)
			}
			if _, err := regexp.Compile(p.Pattern); err != nil {
				return fmt.Errorf("local override %s: redaction pattern %q: invalid regex: %w", path, p.Name, err)
			}
			if seen[p.Name] {
				return fmt.Errorf("local override %s: redaction pattern %d: duplicate name %q", path, i, p.Name)
			}
			seen[p.Name] = true
		}
	}

	if lo.Timeout != "" {
		if _, err := time.ParseDuration(lo.Timeout); err != nil {
			return fmt.Errorf("local override %s: invalid timeout %q: %w", path, lo.Timeout, err)
		}
	}

	if lo.ApprovalTimeout != "" {
		if _, err := time.ParseDuration(lo.ApprovalTimeout); err != nil {
			return fmt.Errorf("local override %s: invalid approval_timeout %q: %w", path, lo.ApprovalTimeout, err)
		}
	}

	if lo.MaxOutputBytes != nil && *lo.MaxOutputBytes < 0 {
		return fmt.Errorf("local override %s: max_output_bytes must be positive, got %d", path, *lo.MaxOutputBytes)
	}

	return nil
}

func validateLocalCEL(rules []PolicyRule) error {
	if len(rules) == 0 {
		return nil
	}

	env, err := cel.NewEnv(
		cel.Variable("method", cel.StringType),
		cel.Variable("server", cel.StringType),
		cel.Variable("tool", cel.MapType(cel.StringType, cel.DynType)),
		cel.Variable("resource", cel.MapType(cel.StringType, cel.DynType)),
	)
	if err != nil {
		return fmt.Errorf("creating CEL environment: %w", err)
	}

	for _, rule := range rules {
		_, issues := env.Compile(rule.Expression)
		if issues != nil && issues.Err() != nil {
			return fmt.Errorf("rule %q: invalid CEL expression: %w", rule.Name, issues.Err())
		}
	}

	return nil
}
