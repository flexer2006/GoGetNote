package logger

import (
	"context"
	"fmt"
	"sync"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

// Переменные для ошибок logger.
var (
	ErrLoggerNotFound   = fmt.Errorf("logger not found in context")
	ErrInitGlobalLogger = fmt.Errorf("failed to initialize global logger")
)

// Глобальный и резервный logger.
var (
	globalLoggerMu sync.RWMutex
	globalLogger   *Logger
	fallbackLogger *Logger
)

// loggerKeyType - тип ключа контекста для предотвращения коллизий.
type loggerKeyType struct{}

var loggerKey = loggerKeyType{}

// Инициализация fallbackLogger при загрузке пакета.
func init() {
	config := zap.NewProductionConfig()
	config.Level = zap.NewAtomicLevelAt(zapcore.WarnLevel)
	zapLogger, _ := config.Build()
	fallbackLogger = &Logger{l: zapLogger.With(zap.String("logger", "fallback"))}
}

// NewContext создает новый контекст с logger.
func NewContext(ctx context.Context, logger *Logger) context.Context {
	return context.WithValue(ctx, loggerKey, logger)
}

// FromContext извлекает logger из контекста.
func FromContext(ctx context.Context) (*Logger, error) {
	if ctx == nil {
		return nil, fmt.Errorf("context validation: %w", ErrLoggerNotFound)
	}
	logger, ok := ctx.Value(loggerKey).(*Logger)
	if !ok {
		return nil, fmt.Errorf("logger lookup: %w", ErrLoggerNotFound)
	}
	return logger, nil
}

// InitGlobalLogger инициализирует глобальный logger.
func InitGlobalLogger(env Environment) error {
	globalLoggerMu.Lock()
	defer globalLoggerMu.Unlock()

	if globalLogger != nil {
		return nil
	}

	var err error
	globalLogger, err = NewLogger(env, "")
	if err != nil {
		return fmt.Errorf("%w: %w", ErrInitGlobalLogger, err)
	}
	return nil
}

// InitGlobalLoggerWithLevel инициализирует глобальный logger с указанным уровнем.
func InitGlobalLoggerWithLevel(env Environment, level string) error {
	globalLoggerMu.Lock()
	defer globalLoggerMu.Unlock()

	if globalLogger != nil {
		return nil
	}

	var err error
	globalLogger, err = NewLogger(env, level)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrInitGlobalLogger, err)
	}
	return nil
}

// SetGlobalLogger устанавливает экземпляр глобального logger.
func SetGlobalLogger(logger *Logger) {
	globalLoggerMu.Lock()
	defer globalLoggerMu.Unlock()
	globalLogger = logger
}

// Log возвращает logger из контекста или глобальный logger.
func Log(ctx context.Context) *Logger {
	if logger, ok := ctx.Value(loggerKey).(*Logger); ok {
		return logger
	}

	globalLoggerMu.RLock()
	if globalLogger != nil {
		defer globalLoggerMu.RUnlock()
		return globalLogger
	}
	globalLoggerMu.RUnlock()

	return fallbackLogger
}
