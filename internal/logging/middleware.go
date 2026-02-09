package logging

import (
	"context"
	"log/slog"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func NewReceivingMiddleware(logger *slog.Logger) mcp.Middleware {
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

			logger.LogAttrs(ctx, slog.LevelInfo, "mcp request", attrs...)

			return result, err
		}
	}
}
