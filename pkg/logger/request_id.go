package logger

import (
	"context"

	"go.uber.org/zap"
)

const (
	RequestID = "request_id"
)

func getRequestID(ctx context.Context) (string, bool) {
	id, ok := ctx.Value(RequestID).(string)
	return id, ok
}

func addRequestID(ctx context.Context, fields []zap.Field) []zap.Field {
	if id, ok := getRequestID(ctx); ok {
		fields = append(fields, zap.String(RequestID, id))
	}
	return fields
}
