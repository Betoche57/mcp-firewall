package logging

import (
	"context"
	"encoding/json"
	"log/slog"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func NewReceivingMiddleware(logger *slog.Logger, hc *HashChain) mcp.Middleware {
	return func(next mcp.MethodHandler) mcp.MethodHandler {
		return func(ctx context.Context, method string, req mcp.Request) (mcp.Result, error) {
			info := &AuditInfo{}
			ctx = WithAuditInfo(ctx, info)

			start := time.Now()
			result, err := next(ctx, method, req)
			duration := time.Since(start)

			attrs := []slog.Attr{
				slog.String("method", method),
				slog.String("direction", "request"),
				slog.Float64("duration_ms", float64(duration.Microseconds())/1000.0),
				slog.Bool("error", err != nil),
			}

			if info.Server != "" {
				attrs = append(attrs, slog.String("server", info.Server))
			}
			if info.ToolName != "" {
				attrs = append(attrs, slog.String("tool", info.ToolName))
			}
			if info.ResourceURI != "" {
				attrs = append(attrs, slog.String("resource_uri", info.ResourceURI))
			}
			if info.PolicyEffect != "" {
				attrs = append(attrs, slog.String("policy_effect", info.PolicyEffect))
			}
			if info.PolicyRule != "" {
				attrs = append(attrs, slog.String("policy_rule", info.PolicyRule))
			}
			if info.ApprovalAction != "" {
				attrs = append(attrs, slog.String("approval_action", info.ApprovalAction))
			}
			if info.Timeout {
				attrs = append(attrs, slog.Bool("timeout", true))
			}
			if info.Truncated {
				attrs = append(attrs, slog.Bool("truncated", true))
			}
			if info.Redacted {
				attrs = append(attrs, slog.Bool("redacted", true))
			}
			if info.Sandboxed {
				attrs = append(attrs, slog.Bool("sandboxed", true))
				if info.SandboxLevel != "" {
					attrs = append(attrs, slog.String("sandbox_level", info.SandboxLevel))
				}
			}
			if info.HashVerified {
				attrs = append(attrs, slog.Bool("hash_verified", true))
			}

			if hc != nil {
				canonical, _ := json.Marshal(attrsToMap(attrs))
				seq, entryHash, prevHash := hc.Next(canonical)
				attrs = append(attrs,
					slog.Uint64("audit_seq", seq),
					slog.String("entry_hash", entryHash),
					slog.String("prev_hash", prevHash),
				)
			}

			logger.LogAttrs(ctx, slog.LevelInfo, "mcp request", attrs...)

			return result, err
		}
	}
}

func attrsToMap(attrs []slog.Attr) map[string]any {
	m := make(map[string]any, len(attrs))
	for _, a := range attrs {
		m[a.Key] = a.Value.Any()
	}
	return m
}
