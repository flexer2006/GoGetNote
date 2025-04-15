package logger

import (
	"context"

	"go.uber.org/zap"
)

// contextKey - специальный тип для ключей контекста
type contextKey string

const (
	RequestID               = "request_id"
	RequestIDKey contextKey = "request_id"
)

func NewRequestIDContext(ctx context.Context, requestID string) context.Context {
	return context.WithValue(ctx, RequestIDKey, requestID)
}

func getRequestID(ctx context.Context) (string, bool) {
	id, ok := ctx.Value(RequestIDKey).(string)
	return id, ok
}

func addRequestID(ctx context.Context, fields []zap.Field) []zap.Field {
	if id, ok := getRequestID(ctx); ok {
		fields = append(fields, zap.String(RequestID, id))
	}
	return fields
}
