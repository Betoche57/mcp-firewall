package logging

import "context"

type contextKey struct{}

type AuditInfo struct {
	Server       string
	ToolName     string
	ResourceURI  string
	PolicyEffect string
	PolicyRule   string
}

func WithAuditInfo(ctx context.Context, info *AuditInfo) context.Context {
	return context.WithValue(ctx, contextKey{}, info)
}

func GetAuditInfo(ctx context.Context) *AuditInfo {
	info, _ := ctx.Value(contextKey{}).(*AuditInfo)
	return info
}
