package logger_test

import (
	"context"
	"testing"

	"gogetnote/pkg/logger"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

func TestAddRequestIDFromContext(t *testing.T) {
	t.Run("context with request ID adds field to logs", func(t *testing.T) {
		requestID := "test-request-id-123"

		ctx := logger.NewRequestIDContext(context.Background(), requestID)

		tempLog, err := logger.NewLogger(logger.Development, "debug")
		require.NoError(t, err)

		tempLog.Info(ctx, "test message")

		logWithReqID := tempLog.WithRequestID(ctx)
		assert.NotSame(t, tempLog, logWithReqID, "WithRequestID should return a new logger when request ID exists")

		emptyCtx := context.Background()
		logWithoutReqID := tempLog.WithRequestID(emptyCtx)
		assert.Same(t, tempLog, logWithoutReqID, "WithRequestID should return same logger when no request ID exists")
	})

	t.Run("context without request ID doesn't add field", func(t *testing.T) {
		tempLog, err := logger.NewLogger(logger.Development, "debug")
		require.NoError(t, err)

		ctx := context.Background()

		logWithoutReqID := tempLog.WithRequestID(ctx)
		assert.Same(t, tempLog, logWithoutReqID, "WithRequestID should return same logger when no request ID exists")

		assert.NotPanics(t, func() {
			tempLog.Info(ctx, "plain context message")
		})
	})

	t.Run("existing fields are preserved", func(t *testing.T) {
		tempLog, err := logger.NewLogger(logger.Development, "debug")
		require.NoError(t, err)

		customField := zap.String("custom_field", "custom-value")
		logWithCustomField := tempLog.With(customField)

		requestID := "test-request-id-456"
		ctx := logger.NewRequestIDContext(context.Background(), requestID)

		logWithBoth := logWithCustomField.WithRequestID(ctx)

		assert.NotSame(t, tempLog, logWithBoth, "Logger with both fields should differ from base logger")
		assert.NotSame(t, logWithCustomField, logWithBoth, "Logger with both fields should differ from logger with only custom field")

		assert.NotPanics(t, func() {
			logWithBoth.Info(ctx, "message with custom field")
		})
	})
}

type Logger struct {
	l *zap.Logger
}

func SetLogger(logger *Logger, zapLogger *zap.Logger) *Logger {
	return &Logger{l: zapLogger}
}
