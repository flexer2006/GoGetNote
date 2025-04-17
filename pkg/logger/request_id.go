package logger

import (
	"context"

	"github.com/google/uuid"
	"go.uber.org/zap"
)

// requestIDKey - ключ контекста для хранения request_id.
type requestIDKeyType struct{}

var requestIDKey = requestIDKeyType{}

// NewRequestIDContext создает новый контекст с идентификатором запроса.
func NewRequestIDContext(ctx context.Context, requestID string) context.Context {
	if requestID == "" {
		requestID = GenerateRequestID()
	}
	return context.WithValue(ctx, requestIDKey, requestID)
}

// GetRequestID извлекает идентификатор запроса из контекста.
func GetRequestID(ctx context.Context) (string, bool) {
	id, ok := ctx.Value(requestIDKey).(string)
	return id, ok
}

// GenerateRequestID генерирует новый идентификатор запроса.
func GenerateRequestID() string {
	return uuid.New().String()
}

// WithRequestID создает копию логгера с добавленным полем RequestID.
func (l *Logger) WithRequestID(ctx context.Context) *Logger {
	if id, ok := GetRequestID(ctx); ok {
		return l.With(zap.String(RequestID, id))
	}
	return l
}
