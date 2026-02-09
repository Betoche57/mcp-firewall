package proxy

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"sort"

	"github.com/VikingOwl91/mcp-firewall/internal/config"
	"github.com/VikingOwl91/mcp-firewall/internal/logging"
	"github.com/VikingOwl91/mcp-firewall/internal/policy"
	"github.com/VikingOwl91/mcp-firewall/internal/redaction"
	"github.com/VikingOwl91/mcp-firewall/internal/sandbox"
	"github.com/VikingOwl91/mcp-firewall/internal/supply"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

type downstreamEntry struct {
	client  *mcp.Client
	session *mcp.ClientSession
}

type Proxy struct {
	cfg                 *config.Config
	logger              *slog.Logger
	server              *mcp.Server
	downstreams         map[string]*downstreamEntry
	policy              *policy.Engine
	redaction           *redaction.Engine
	resourceRoutes      map[string]string // URI → alias
	version             string
	profileName         string
	localOverridePath   string
	workspacePath       string
	sandboxCaps         *sandbox.Capabilities
	supplyChainResults  map[string]*supply.VerifyResult
}

// ProxyOption configures optional Proxy behavior.
type ProxyOption func(*Proxy)

// WithProvenance sets provenance metadata for the explain tool.
func WithProvenance(profile, localPath string) ProxyOption {
	return func(p *Proxy) {
		p.profileName = profile
		p.localOverridePath = localPath
	}
}

// WithVersion sets the version string for the MCP Implementation.
func WithVersion(v string) ProxyOption {
	return func(p *Proxy) {
		p.version = v
	}
}

// WithWorkspace sets the workspace path for sandbox workspace access.
func WithWorkspace(path string) ProxyOption {
	return func(p *Proxy) {
		p.workspacePath = path
	}
}

func New(cfg *config.Config, logger *slog.Logger, opts ...ProxyOption) *Proxy {
	p := &Proxy{
		cfg:            cfg,
		logger:         logger,
		downstreams:    make(map[string]*downstreamEntry),
		resourceRoutes: make(map[string]string),
		version:        "dev",
	}

	for _, opt := range opts {
		opt(p)
	}

	server := mcp.NewServer(&mcp.Implementation{
		Name:    "mcp-firewall",
		Version: p.version,
	}, &mcp.ServerOptions{
		Logger: logger,
	})

	hc := logging.NewHashChain()
	server.AddReceivingMiddleware(logging.NewReceivingMiddleware(logger, hc))

	var pe *policy.Engine
	if len(cfg.Policy.Rules) > 0 || cfg.Policy.Default != "allow" {
		var err error
		pe, err = policy.New(cfg.Policy)
		if err != nil {
			logger.Error("failed to create policy engine", slog.String("error", err.Error()))
		}
	}

	var re *redaction.Engine
	if len(cfg.Redaction.Patterns) > 0 {
		var err error
		re, err = redaction.New(cfg.Redaction.Patterns)
		if err != nil {
			logger.Error("failed to create redaction engine", slog.String("error", err.Error()))
		}
	}

	p.server = server
	p.policy = pe
	p.redaction = re

	return p
}

func (p *Proxy) ConnectDownstream(ctx context.Context, alias string, t mcp.Transport) error {
	client := mcp.NewClient(&mcp.Implementation{
		Name:    "mcp-firewall-client",
		Version: p.version,
	}, nil)

	session, err := client.Connect(ctx, t, nil)
	if err != nil {
		return fmt.Errorf("connecting to downstream %q: %w", alias, err)
	}

	p.downstreams[alias] = &downstreamEntry{
		client:  client,
		session: session,
	}
	return nil
}

func (p *Proxy) RegisterUpstreamHandlers(ctx context.Context) error {
	// Register firewall introspection tool
	p.registerExplainTool()

	// Process downstreams in sorted order for deterministic tool/resource registration
	aliases := make([]string, 0, len(p.downstreams))
	for alias := range p.downstreams {
		aliases = append(aliases, alias)
	}
	sort.Strings(aliases)

	for _, alias := range aliases {
		entry := p.downstreams[alias]
		if err := p.registerTools(ctx, alias, entry.session); err != nil {
			return fmt.Errorf("registering tools for %q: %w", alias, err)
		}
		if err := p.registerResources(ctx, alias, entry.session); err != nil {
			return fmt.Errorf("registering resources for %q: %w", alias, err)
		}
	}
	return nil
}

func (p *Proxy) registerTools(ctx context.Context, alias string, session *mcp.ClientSession) error {
	result, err := session.ListTools(ctx, nil)
	if err != nil {
		return err
	}

	for _, tool := range result.Tools {
		tool := tool
		originalName := tool.Name
		tool.Name = namespacedToolName(alias, originalName)

		serverAlias := alias
		ds := session
		sandboxed := p.isDownstreamSandboxed(serverAlias)
		hashVerified := p.isDownstreamHashVerified(serverAlias)
		p.server.AddTool(tool, func(ctx context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			if info := logging.GetAuditInfo(ctx); info != nil {
				info.Server = serverAlias
				info.ToolName = originalName
				if sandboxed {
					info.Sandboxed = true
					if p.sandboxCaps != nil {
						info.SandboxLevel = p.sandboxCaps.EffectiveLevel()
					}
				}
				if hashVerified {
					info.HashVerified = true
				}
			}

			var argsMap map[string]any
			if len(req.Params.Arguments) > 0 {
				if err := json.Unmarshal(req.Params.Arguments, &argsMap); err != nil {
					return nil, fmt.Errorf("unmarshaling arguments: %w", err)
				}
			}

			if p.policy != nil {
				rc := policy.RequestContext{
					Method: "tools/call",
					Server: serverAlias,
					Tool: policy.ToolContext{
						Name:      originalName,
						Arguments: argsMap,
					},
				}
				decision := p.policy.Evaluate(rc)
				if info := logging.GetAuditInfo(ctx); info != nil {
					info.PolicyEffect = string(decision.Effect)
					info.PolicyRule = decision.Rule
				}
				if decision.Effect == policy.Deny {
					return &mcp.CallToolResult{
						Content: []mcp.Content{&mcp.TextContent{Text: fmt.Sprintf("denied by policy: %s", decision.Rule)}},
						IsError: true,
					}, nil
				}
				if decision.Effect == policy.Prompt {
					action, err := requestApproval(ctx, req.Session, decision, p.cfg.ResolvedApprovalTimeout())
					if info := logging.GetAuditInfo(ctx); info != nil {
						info.ApprovalAction = action
					}
					if err != nil {
						return &mcp.CallToolResult{
							Content: []mcp.Content{&mcp.TextContent{Text: err.Error()}},
							IsError: true,
						}, nil
					}
				}
			}

			// Input redaction
			callArgs := argsMap
			if p.redaction != nil && callArgs != nil {
				redacted, matched := p.redaction.RedactMap(callArgs)
				if len(matched) > 0 {
					callArgs = redacted
					if info := logging.GetAuditInfo(ctx); info != nil {
						info.Redacted = true
					}
				}
			}

			var args any
			if callArgs != nil {
				args = callArgs
			}

			timeout := p.cfg.ResolvedTimeout(serverAlias)
			callCtx, callCancel := context.WithTimeout(ctx, timeout)
			defer callCancel()

			result, err := ds.CallTool(callCtx, &mcp.CallToolParams{
				Name:      originalName,
				Arguments: args,
			})
			if err != nil {
				if errors.Is(err, context.DeadlineExceeded) {
					if info := logging.GetAuditInfo(ctx); info != nil {
						info.Timeout = true
					}
					return &mcp.CallToolResult{
						Content: []mcp.Content{&mcp.TextContent{Text: fmt.Sprintf("timeout after %s", timeout)}},
						IsError: true,
					}, nil
				}
				return nil, err
			}

			// Output redaction
			if result != nil && p.redaction != nil {
				redacted, matched := p.redaction.RedactContent(result.Content)
				if len(matched) > 0 {
					result.Content = redacted
					if info := logging.GetAuditInfo(ctx); info != nil {
						info.Redacted = true
					}
				}
			}

			if result != nil && p.cfg.MaxOutputBytes > 0 {
				truncated, wasTruncated := TruncateContent(result.Content, p.cfg.MaxOutputBytes)
				if wasTruncated {
					result.Content = truncated
					if info := logging.GetAuditInfo(ctx); info != nil {
						info.Truncated = true
					}
				}
			}

			return result, nil
		})

		p.logger.Info("registered proxied tool",
			slog.String("name", tool.Name),
			slog.String("server", alias),
		)
	}

	return nil
}

func (p *Proxy) registerResources(ctx context.Context, alias string, session *mcp.ClientSession) error {
	result, err := session.ListResources(ctx, nil)
	if err != nil {
		return err
	}

	for _, res := range result.Resources {
		res := res
		res.Name = namespacedResourceName(alias, res.Name)

		p.resourceRoutes[res.URI] = alias

		serverAlias := alias
		ds := session
		sandboxed := p.isDownstreamSandboxed(serverAlias)
		hashVerified := p.isDownstreamHashVerified(serverAlias)
		p.server.AddResource(res, func(ctx context.Context, req *mcp.ReadResourceRequest) (*mcp.ReadResourceResult, error) {
			if info := logging.GetAuditInfo(ctx); info != nil {
				info.Server = serverAlias
				info.ResourceURI = req.Params.URI
				if sandboxed {
					info.Sandboxed = true
					if p.sandboxCaps != nil {
						info.SandboxLevel = p.sandboxCaps.EffectiveLevel()
					}
				}
				if hashVerified {
					info.HashVerified = true
				}
			}

			if p.policy != nil {
				rc := policy.RequestContext{
					Method: "resources/read",
					Server: serverAlias,
					Resource: policy.ResourceContext{
						URI: req.Params.URI,
					},
				}
				decision := p.policy.Evaluate(rc)
				if info := logging.GetAuditInfo(ctx); info != nil {
					info.PolicyEffect = string(decision.Effect)
					info.PolicyRule = decision.Rule
				}
				if decision.Effect == policy.Deny {
					return nil, fmt.Errorf("denied by policy: %s", decision.Rule)
				}
				if decision.Effect == policy.Prompt {
					action, err := requestApproval(ctx, req.Session, decision, p.cfg.ResolvedApprovalTimeout())
					if info := logging.GetAuditInfo(ctx); info != nil {
						info.ApprovalAction = action
					}
					if err != nil {
						return nil, err
					}
				}
			}

			timeout := p.cfg.ResolvedTimeout(serverAlias)
			readCtx, readCancel := context.WithTimeout(ctx, timeout)
			defer readCancel()

			result, err := ds.ReadResource(readCtx, &mcp.ReadResourceParams{
				URI: req.Params.URI,
			})
			if err != nil {
				if errors.Is(err, context.DeadlineExceeded) {
					if info := logging.GetAuditInfo(ctx); info != nil {
						info.Timeout = true
					}
					return nil, fmt.Errorf("timeout after %s", timeout)
				}
				return nil, err
			}

			// Output redaction
			if result != nil && p.redaction != nil {
				redacted, matched := p.redaction.RedactResourceContents(result.Contents)
				if len(matched) > 0 {
					result.Contents = redacted
					if info := logging.GetAuditInfo(ctx); info != nil {
						info.Redacted = true
					}
				}
			}

			if result != nil && p.cfg.MaxOutputBytes > 0 {
				truncated, wasTruncated := TruncateResourceContents(result.Contents, p.cfg.MaxOutputBytes)
				if wasTruncated {
					result.Contents = truncated
					if info := logging.GetAuditInfo(ctx); info != nil {
						info.Truncated = true
					}
				}
			}

			return result, nil
		})

		p.logger.Info("registered proxied resource",
			slog.String("name", res.Name),
			slog.String("uri", res.URI),
			slog.String("server", alias),
		)
	}

	return nil
}

func (p *Proxy) ServeUpstream(ctx context.Context, t mcp.Transport) error {
	return p.server.Run(ctx, t)
}

func (p *Proxy) isDownstreamSandboxed(alias string) bool {
	sc, ok := p.cfg.Downstreams[alias]
	return ok && sc.Sandbox != "" && sc.Sandbox != "none"
}

func (p *Proxy) isDownstreamHashVerified(alias string) bool {
	r, ok := p.supplyChainResults[alias]
	return ok && r != nil && r.ComputedHash != ""
}

// toSandboxProfiles converts config sandbox profiles to sandbox package types.
func toSandboxProfiles(cfgProfiles map[string]config.SandboxProfileConfig) map[string]sandbox.SandboxProfileConfig {
	if len(cfgProfiles) == 0 {
		return nil
	}
	result := make(map[string]sandbox.SandboxProfileConfig, len(cfgProfiles))
	for name, p := range cfgProfiles {
		result[name] = sandbox.SandboxProfileConfig{
			Network:      p.Network,
			EnvAllowlist: p.EnvAllowlist,
			FSDeny:       p.FSDeny,
			FSAllowRO:    p.FSAllowRO,
			FSAllowRW:    p.FSAllowRW,
			Workspace:    p.Workspace,
		}
	}
	return result
}

func (p *Proxy) verifySupplyChain(alias string, sc config.ServerConfig) (*supply.VerifyResult, error) {
	hasHash := sc.Hash != ""
	hasPaths := len(p.cfg.SupplyChain.AllowedPaths) > 0

	if !hasHash && !hasPaths {
		return nil, nil
	}

	result, err := supply.Verify(sc.Command, sc.Hash, p.cfg.SupplyChain.AllowedPaths)
	if err != nil {
		return nil, fmt.Errorf("downstream %q: %w", alias, err)
	}

	attrs := []any{
		slog.String("alias", alias),
		slog.String("resolved_path", result.ResolvedPath),
	}
	if result.ComputedHash != "" {
		attrs = append(attrs, slog.String("hash", result.ComputedHash), slog.Bool("hash_verified", true))
	}
	if hasPaths {
		attrs = append(attrs, slog.Bool("path_verified", true))
	}
	p.logger.Info("supply chain verified", attrs...)

	return result, nil
}

func (p *Proxy) Run(ctx context.Context, upstream mcp.Transport) error {
	// Detect sandbox capabilities once
	caps := sandbox.DetectCapabilities()
	p.sandboxCaps = &caps

	// Verify supply chain for all downstreams before spawning any
	p.supplyChainResults = make(map[string]*supply.VerifyResult)
	for alias, sc := range p.cfg.Downstreams {
		result, err := p.verifySupplyChain(alias, sc)
		if err != nil {
			return err
		}
		if result != nil {
			p.supplyChainResults[alias] = result
		}
	}

	selfPath, _ := os.Executable()

	for alias, sc := range p.cfg.Downstreams {
		var cmd *exec.Cmd

		if sc.Sandbox != "" && sc.Sandbox != "none" {
			profile, err := sandbox.ResolveProfile(sc.Sandbox, toSandboxProfiles(p.cfg.SandboxProfiles))
			if err != nil {
				return fmt.Errorf("downstream %q: %w", alias, err)
			}
			cmd, err = sandbox.BuildSandboxedCmd(
				ctx, selfPath, profile, caps,
				sc.Command, sc.Args, sc.Env, p.workspacePath,
			)
			if err != nil {
				return fmt.Errorf("downstream %q sandbox: %w", alias, err)
			}
			p.logger.Info("sandboxed downstream",
				slog.String("alias", alias),
				slog.String("profile", sc.Sandbox),
				slog.String("level", caps.EffectiveLevel()),
			)
		} else {
			cmd = exec.CommandContext(ctx, sc.Command, sc.Args...)
			cmd.Env = append(cmd.Environ(), sc.Env...)
		}

		t := &mcp.CommandTransport{Command: cmd}
		if err := p.ConnectDownstream(ctx, alias, t); err != nil {
			return err
		}
	}

	defer func() {
		for _, entry := range p.downstreams {
			entry.session.Close()
		}
	}()

	if err := p.RegisterUpstreamHandlers(ctx); err != nil {
		return err
	}

	p.logger.Info("proxy ready, serving upstream",
		slog.Int("downstreams", len(p.downstreams)),
	)
	return p.ServeUpstream(ctx, upstream)
}
