package config

import (
	"fmt"
	"time"
)

// MergeLocal applies a LocalOverride to a base Config.
// By default, local overrides can only restrict (tighten) the base.
// If allowExpansion is true, local allow rules are also accepted.
// Returns a new *Config (does not mutate base).
func MergeLocal(base *Config, local *LocalOverride, allowExpansion bool) (*Config, error) {
	if local == nil {
		result := copyConfig(base)
		return result, nil
	}

	result := copyConfig(base)

	if err := mergePolicy(result, local, allowExpansion); err != nil {
		return nil, err
	}

	if err := mergeRedaction(result, local); err != nil {
		return nil, err
	}

	if err := mergeTimeout(result, local); err != nil {
		return nil, err
	}

	if err := mergeApprovalTimeout(result, local); err != nil {
		return nil, err
	}

	mergeMaxOutputBytes(result, local)
	mergeLogLevel(result, local)

	return result, nil
}

func mergePolicy(result *Config, local *LocalOverride, allowExpansion bool) error {
	if local.Policy == nil {
		return nil
	}

	if local.Policy.Default != "" {
		return fmt.Errorf("local override cannot set policy.default")
	}

	// Check for allow rules when expansion is not permitted
	if !allowExpansion {
		for _, rule := range local.Policy.Rules {
			if rule.Effect == "allow" {
				return fmt.Errorf("local override rule %q has effect 'allow', which is not permitted without allow_expansion", rule.Name)
			}
		}
	}

	// Check for duplicate rule names
	baseNames := make(map[string]bool, len(result.Policy.Rules))
	for _, rule := range result.Policy.Rules {
		baseNames[rule.Name] = true
	}
	for _, rule := range local.Policy.Rules {
		if baseNames[rule.Name] {
			return fmt.Errorf("local override rule %q conflicts with existing rule (duplicate name)", rule.Name)
		}
	}

	// Prepend local rules (first-match-wins → local restrictions take priority)
	localRules := make([]PolicyRule, len(local.Policy.Rules))
	for i, rule := range local.Policy.Rules {
		rule.Source = "local"
		localRules[i] = rule
	}

	merged := make([]PolicyRule, 0, len(localRules)+len(result.Policy.Rules))
	merged = append(merged, localRules...)
	merged = append(merged, result.Policy.Rules...)
	result.Policy.Rules = merged

	return nil
}

func mergeRedaction(result *Config, local *LocalOverride) error {
	if local.Redaction == nil {
		return nil
	}

	// Check for duplicate pattern names
	baseNames := make(map[string]bool, len(result.Redaction.Patterns))
	for _, p := range result.Redaction.Patterns {
		baseNames[p.Name] = true
	}
	for _, p := range local.Redaction.Patterns {
		if baseNames[p.Name] {
			return fmt.Errorf("local override redaction pattern %q conflicts with existing pattern (duplicate name)", p.Name)
		}
	}

	// Append local patterns (more redaction = more restrictive)
	for _, p := range local.Redaction.Patterns {
		p.Source = "local"
		result.Redaction.Patterns = append(result.Redaction.Patterns, p)
	}

	return nil
}

func mergeTimeout(result *Config, local *LocalOverride) error {
	if local.Timeout == "" {
		return nil
	}

	localDur, err := time.ParseDuration(local.Timeout)
	if err != nil {
		return fmt.Errorf("local override invalid timeout %q: %w", local.Timeout, err)
	}

	baseDur, _ := time.ParseDuration(result.Timeout)

	// Only accept if lower (more restrictive)
	if localDur < baseDur {
		result.Timeout = local.Timeout
	}

	return nil
}

func mergeApprovalTimeout(result *Config, local *LocalOverride) error {
	if local.ApprovalTimeout == "" {
		return nil
	}

	localDur, err := time.ParseDuration(local.ApprovalTimeout)
	if err != nil {
		return fmt.Errorf("local override invalid approval_timeout %q: %w", local.ApprovalTimeout, err)
	}

	baseDur, _ := time.ParseDuration(result.ApprovalTimeout)

	if localDur < baseDur {
		result.ApprovalTimeout = local.ApprovalTimeout
	}

	return nil
}

func mergeMaxOutputBytes(result *Config, local *LocalOverride) {
	if local.MaxOutputBytes == nil {
		return
	}

	if *local.MaxOutputBytes > 0 && *local.MaxOutputBytes < result.MaxOutputBytes {
		result.MaxOutputBytes = *local.MaxOutputBytes
	}
}

func mergeLogLevel(result *Config, local *LocalOverride) {
	if local.LogLevel != "" {
		result.LogLevel = local.LogLevel
	}
}

// copyConfig creates a shallow copy of a Config with deep-copied slices.
func copyConfig(c *Config) *Config {
	result := *c

	// Deep copy downstreams map
	result.Downstreams = make(map[string]ServerConfig, len(c.Downstreams))
	for k, v := range c.Downstreams {
		result.Downstreams[k] = v
	}

	// Deep copy policy rules
	result.Policy.Rules = make([]PolicyRule, len(c.Policy.Rules))
	copy(result.Policy.Rules, c.Policy.Rules)

	// Deep copy redaction patterns
	result.Redaction.Patterns = make([]RedactionPattern, len(c.Redaction.Patterns))
	copy(result.Redaction.Patterns, c.Redaction.Patterns)

	// Deep copy sandbox profiles
	if len(c.SandboxProfiles) > 0 {
		result.SandboxProfiles = make(map[string]SandboxProfileConfig, len(c.SandboxProfiles))
		for k, v := range c.SandboxProfiles {
			result.SandboxProfiles[k] = v
		}
	}

	return &result
}
