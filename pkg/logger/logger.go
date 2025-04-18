// Package logger предоставляет функциональность логирования для приложения,
// включая контекстное логирование, глобальные loggers и утилиты для работы с логами.
package logger

import (
	"context"
	"fmt"
	"strings"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

const (
	// ErrInitializeLogger сообщение об ошибке, возникающей при инициализации logger.
	ErrInitializeLogger = "failed to initialize logger"
)

const (
	// RequestID ключ для идентификатора запроса в контексте.
	RequestID = "request_id"
)

// Logger оборачивает zap.Logger.
type Logger struct {
	l *zap.Logger
}

// Environment представляет конфигурацию окружения logger.
type Environment string

const (
	// Development включает более подробную запись, подходящую для разработки.
	Development Environment = "development"
	// Production включает оптимизированную запись для использования в продакшене.
	Production Environment = "production"
)

// NewLogger создает новый logger с указанными окружением и уровнем.
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

// With создает новый logger с дополнительными полями.
func (l *Logger) With(fields ...zap.Field) *Logger {
	return &Logger{l: l.l.With(fields...)}
}

// Info записывает сообщение на уровне Info.
func (l *Logger) Info(ctx context.Context, msg string, fields ...zap.Field) {
	fields = addRequestIDFromContext(ctx, fields)
	l.l.Info(msg, fields...)
}

// Warn записывает сообщение на уровне Warn.
func (l *Logger) Warn(ctx context.Context, msg string, fields ...zap.Field) {
	fields = addRequestIDFromContext(ctx, fields)
	l.l.Warn(msg, fields...)
}

// Error записывает сообщение на уровне Error.
func (l *Logger) Error(ctx context.Context, msg string, fields ...zap.Field) {
	fields = addRequestIDFromContext(ctx, fields)
	l.l.Error(msg, fields...)
}

// Debug записывает сообщение на уровне Debug.
func (l *Logger) Debug(ctx context.Context, msg string, fields ...zap.Field) {
	fields = addRequestIDFromContext(ctx, fields)
	l.l.Debug(msg, fields...)
}

// Fatal записывает сообщение на уровне Fatal и завершает программу.
func (l *Logger) Fatal(ctx context.Context, msg string, fields ...zap.Field) {
	fields = addRequestIDFromContext(ctx, fields)
	l.l.Fatal(msg, fields...)
}

// Sync сбрасывает все буферизованные записи logger.
func (l *Logger) Sync() error {
	if err := l.l.Sync(); err != nil {
		return fmt.Errorf("failed to sync logger: %w", err)
	}
	return nil
}

// addRequestIDFromContext добавляет requestID из контекста в поля logger.
func addRequestIDFromContext(ctx context.Context, fields []zap.Field) []zap.Field {
	if id, ok := GetRequestID(ctx); ok {
		return append(fields, zap.String(RequestID, id))
	}
	return fields
}
