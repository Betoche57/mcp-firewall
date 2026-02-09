package proxy

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os/exec"
	"sort"

	"github.com/VikingOwl91/mcp-firewall/internal/config"
	"github.com/VikingOwl91/mcp-firewall/internal/logging"
	"github.com/VikingOwl91/mcp-firewall/internal/policy"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

type downstreamEntry struct {
	client  *mcp.Client
	session *mcp.ClientSession
}

type Proxy struct {
	cfg            *config.Config
	logger         *slog.Logger
	server         *mcp.Server
	downstreams    map[string]*downstreamEntry
	policy         *policy.Engine
	resourceRoutes map[string]string // URI → alias
}

func New(cfg *config.Config, logger *slog.Logger) *Proxy {
	server := mcp.NewServer(&mcp.Implementation{
		Name:    "mcp-firewall",
		Version: "0.2.0",
	}, &mcp.ServerOptions{
		Logger: logger,
	})

	server.AddReceivingMiddleware(logging.NewReceivingMiddleware(logger))

	var pe *policy.Engine
	if len(cfg.Policy.Rules) > 0 || cfg.Policy.Default != "allow" {
		var err error
		pe, err = policy.New(cfg.Policy)
		if err != nil {
			logger.Error("failed to create policy engine", slog.String("error", err.Error()))
		}
	}

	return &Proxy{
		cfg:            cfg,
		logger:         logger,
		server:         server,
		downstreams:    make(map[string]*downstreamEntry),
		policy:         pe,
		resourceRoutes: make(map[string]string),
	}
}

func (p *Proxy) ConnectDownstream(ctx context.Context, alias string, t mcp.Transport) error {
	client := mcp.NewClient(&mcp.Implementation{
		Name:    "mcp-firewall-client",
		Version: "0.2.0",
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
		p.server.AddTool(tool, func(ctx context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			if info := logging.GetAuditInfo(ctx); info != nil {
				info.Server = serverAlias
				info.ToolName = originalName
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
				effect, rule := p.policy.Evaluate(rc)
				if info := logging.GetAuditInfo(ctx); info != nil {
					info.PolicyEffect = string(effect)
					info.PolicyRule = rule
				}
				if effect == policy.Deny {
					return &mcp.CallToolResult{
						Content: []mcp.Content{&mcp.TextContent{Text: fmt.Sprintf("denied by policy: %s", rule)}},
						IsError: true,
					}, nil
				}
			}

			var args any
			if argsMap != nil {
				args = argsMap
			}

			return ds.CallTool(ctx, &mcp.CallToolParams{
				Name:      originalName,
				Arguments: args,
			})
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
		p.server.AddResource(res, func(ctx context.Context, req *mcp.ReadResourceRequest) (*mcp.ReadResourceResult, error) {
			if info := logging.GetAuditInfo(ctx); info != nil {
				info.Server = serverAlias
				info.ResourceURI = req.Params.URI
			}

			if p.policy != nil {
				rc := policy.RequestContext{
					Method: "resources/read",
					Server: serverAlias,
					Resource: policy.ResourceContext{
						URI: req.Params.URI,
					},
				}
				effect, rule := p.policy.Evaluate(rc)
				if info := logging.GetAuditInfo(ctx); info != nil {
					info.PolicyEffect = string(effect)
					info.PolicyRule = rule
				}
				if effect == policy.Deny {
					return nil, fmt.Errorf("denied by policy: %s", rule)
				}
			}

			return ds.ReadResource(ctx, &mcp.ReadResourceParams{
				URI: req.Params.URI,
			})
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

func (p *Proxy) Run(ctx context.Context, upstream mcp.Transport) error {
	for alias, sc := range p.cfg.Downstreams {
		cmd := exec.CommandContext(ctx, sc.Command, sc.Args...)
		cmd.Env = append(cmd.Environ(), sc.Env...)

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
