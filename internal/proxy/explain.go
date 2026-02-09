package proxy

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

type explainOutput struct {
	Profile         string               `json:"profile,omitempty"`
	LocalOverride   string               `json:"local_override,omitempty"`
	Policy          explainPolicy        `json:"policy"`
	Redaction       explainRedaction     `json:"redaction,omitempty"`
	Timeout         string               `json:"timeout"`
	ApprovalTimeout string               `json:"approval_timeout"`
	MaxOutputBytes  int                  `json:"max_output_bytes"`
	LogLevel        string               `json:"log_level"`
	Sandbox         *explainSandbox      `json:"sandbox,omitempty"`
	SupplyChain     *explainSupplyChain  `json:"supply_chain,omitempty"`
}

type explainSupplyChain struct {
	AllowedPaths []string                       `json:"allowed_paths,omitempty"`
	Downstreams  map[string]explainDownstreamSC `json:"downstreams"`
}

type explainDownstreamSC struct {
	Hash         string `json:"hash,omitempty"`
	ComputedHash string `json:"computed_hash,omitempty"`
	ResolvedPath string `json:"resolved_path,omitempty"`
}

type explainPolicy struct {
	Default string              `json:"default"`
	Rules   []explainPolicyRule `json:"rules,omitempty"`
}

type explainPolicyRule struct {
	Name       string `json:"name"`
	Expression string `json:"expression"`
	Effect     string `json:"effect"`
	Message    string `json:"message,omitempty"`
	Source     string `json:"source,omitempty"`
}

type explainRedaction struct {
	Patterns []explainRedactionPattern `json:"patterns,omitempty"`
}

type explainRedactionPattern struct {
	Name    string `json:"name"`
	Pattern string `json:"pattern"`
	Source  string `json:"source,omitempty"`
}

type explainSandbox struct {
	Capabilities explainSandboxCaps `json:"capabilities"`
	Downstreams  map[string]string  `json:"downstreams"` // alias → profile name
}

type explainSandboxCaps struct {
	UserNamespace bool `json:"user_namespace"`
	Landlock      bool `json:"landlock"`
	LandlockABI   int  `json:"landlock_abi"`
}

func (p *Proxy) registerExplainTool() {
	p.server.AddTool(&mcp.Tool{
		Name:        "explain_effective_policy",
		Description: "Show the effective firewall policy with provenance",
		InputSchema: json.RawMessage(`{"type":"object"}`),
	}, func(_ context.Context, _ *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		return p.handleExplainPolicy()
	})
}

func (p *Proxy) handleExplainPolicy() (*mcp.CallToolResult, error) {
	output := explainOutput{
		Profile:         p.profileName,
		LocalOverride:   p.localOverridePath,
		Timeout:         p.cfg.Timeout,
		ApprovalTimeout: p.cfg.ApprovalTimeout,
		MaxOutputBytes:  p.cfg.MaxOutputBytes,
		LogLevel:        p.cfg.LogLevel,
		Policy: explainPolicy{
			Default: p.cfg.Policy.Default,
		},
	}

	for _, rule := range p.cfg.Policy.Rules {
		output.Policy.Rules = append(output.Policy.Rules, explainPolicyRule{
			Name:       rule.Name,
			Expression: rule.Expression,
			Effect:     rule.Effect,
			Message:    rule.Message,
			Source:     rule.Source,
		})
	}

	for _, pat := range p.cfg.Redaction.Patterns {
		output.Redaction.Patterns = append(output.Redaction.Patterns, explainRedactionPattern{
			Name:    pat.Name,
			Pattern: pat.Pattern,
			Source:  pat.Source,
		})
	}

	// Add sandbox info if any downstream uses sandbox
	output.Sandbox = p.buildExplainSandbox()

	// Add supply chain info if configured
	output.SupplyChain = p.buildExplainSupplyChain()

	data, err := json.MarshalIndent(output, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("marshaling policy explanation: %w", err)
	}

	return &mcp.CallToolResult{
		Content: []mcp.Content{&mcp.TextContent{Text: string(data)}},
	}, nil
}

func (p *Proxy) buildExplainSandbox() *explainSandbox {
	downstreams := make(map[string]string)
	hasSandbox := false
	for alias, sc := range p.cfg.Downstreams {
		if sc.Sandbox != "" && sc.Sandbox != "none" {
			downstreams[alias] = sc.Sandbox
			hasSandbox = true
		} else {
			downstreams[alias] = "none"
		}
	}

	if !hasSandbox {
		return nil
	}

	s := &explainSandbox{
		Downstreams: downstreams,
	}
	if p.sandboxCaps != nil {
		s.Capabilities = explainSandboxCaps{
			UserNamespace: p.sandboxCaps.UserNamespace,
			Landlock:      p.sandboxCaps.Landlock,
			LandlockABI:   p.sandboxCaps.LandlockABI,
		}
	}
	return s
}

func (p *Proxy) buildExplainSupplyChain() *explainSupplyChain {
	hasAny := len(p.cfg.SupplyChain.AllowedPaths) > 0
	for _, sc := range p.cfg.Downstreams {
		if sc.Hash != "" {
			hasAny = true
			break
		}
	}
	if !hasAny {
		return nil
	}

	sc := &explainSupplyChain{
		AllowedPaths: p.cfg.SupplyChain.AllowedPaths,
		Downstreams:  make(map[string]explainDownstreamSC),
	}

	for alias, cfg := range p.cfg.Downstreams {
		dsc := explainDownstreamSC{
			Hash: cfg.Hash,
		}
		if r, ok := p.supplyChainResults[alias]; ok && r != nil {
			dsc.ComputedHash = r.ComputedHash
			dsc.ResolvedPath = r.ResolvedPath
		}
		sc.Downstreams[alias] = dsc
	}

	return sc
}
