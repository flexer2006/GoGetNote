package logger

import (
	"context"
	"fmt"
	"strings"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

// Константы для сообщений об ошибках логгера.
const (
	ErrInitializeLogger = "failed to initialize logger"
)

// Константы для полей logger.
const (
	RequestID   = "request_id"
	FieldLogger = "logger"
)

// Logger оборачивает zap.Logger.
type Logger struct {
	l *zap.Logger
}

// Environment представляет конфигурацию окружения логгера.
type Environment string

const (
	// Development включает более подробное логгирование, подходящее для разработки.
	Development Environment = "development"
	// Production включает оптимизированное логгирование для использования в продакшене.
	Production Environment = "production"
)

// NewLogger создает новый логгер с указанными окружением и уровнем.
func NewLogger(env Environment, level string) (*Logger, error) {
	var zapLevel zapcore.Level

	switch strings.ToLower(level) {
	case "debug":
		zapLevel = zapcore.DebugLevel
	case "info":
		zapLevel = zapcore.InfoLevel
	case "warn", "warning":
		zapLevel = zapcore.WarnLevel
	case "error":
		zapLevel = zapcore.ErrorLevel
	default:
		if env == Production {
			zapLevel = zapcore.InfoLevel
		} else {
			zapLevel = zapcore.DebugLevel
		}
	}

	var zapLogger *zap.Logger
	var err error

	if env == Production {
		config := zap.NewProductionConfig()
		config.Level = zap.NewAtomicLevelAt(zapLevel)
		zapLogger, err = config.Build()
	} else {
		config := zap.NewDevelopmentConfig()
		config.Level = zap.NewAtomicLevelAt(zapLevel)
		zapLogger, err = config.Build()
	}

	if err != nil {
		return nil, fmt.Errorf("%s: %w", ErrInitializeLogger, err)
	}

	return &Logger{l: zapLogger}, nil
}

// With создает новый логгер с дополнительными полями.
func (l *Logger) With(fields ...zap.Field) *Logger {
	return &Logger{l: l.l.With(fields...)}
}

// Info логгирует сообщение на уровне Info.
func (l *Logger) Info(ctx context.Context, msg string, fields ...zap.Field) {
	fields = addRequestIDFromContext(ctx, fields)
	l.l.Info(msg, fields...)
}

// Warn логгирует сообщение на уровне Warn.
func (l *Logger) Warn(ctx context.Context, msg string, fields ...zap.Field) {
	fields = addRequestIDFromContext(ctx, fields)
	l.l.Warn(msg, fields...)
}

// Error логгирует сообщение на уровне Error.
func (l *Logger) Error(ctx context.Context, msg string, fields ...zap.Field) {
	fields = addRequestIDFromContext(ctx, fields)
	l.l.Error(msg, fields...)
}

// Debug логгирует сообщение на уровне Debug.
func (l *Logger) Debug(ctx context.Context, msg string, fields ...zap.Field) {
	fields = addRequestIDFromContext(ctx, fields)
	l.l.Debug(msg, fields...)
}

// Fatal логгирует сообщение на уровне Fatal и завершает программу.
func (l *Logger) Fatal(ctx context.Context, msg string, fields ...zap.Field) {
	fields = addRequestIDFromContext(ctx, fields)
	l.l.Fatal(msg, fields...)
}

// Sync сбрасывает все буферизованные записи логгера.
func (l *Logger) Sync() error {
	return l.l.Sync()
}

// addRequestIDFromContext добавляет requestID из контекста в поля логгера.
func addRequestIDFromContext(ctx context.Context, fields []zap.Field) []zap.Field {
	if id, ok := GetRequestID(ctx); ok {
		return append(fields, zap.String(RequestID, id))
	}
	return fields
}
