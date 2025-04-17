package logger_test

import (
	"context"
	"testing"

	"gogetnote/pkg/logger"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

func TestLoggerMethods(t *testing.T) {
	log, err := logger.NewLogger(logger.Development, "debug")
	require.NoError(t, err)
	require.NotNil(t, log)

	t.Run("With creates new logger instance", func(t *testing.T) {
		field := zap.String("key", "value")
		newLog := log.With(field)

		assert.NotNil(t, newLog)
		assert.NotSame(t, log, newLog, "With() should return a new logger instance")
	})

	t.Run("With multiple fields", func(t *testing.T) {
		field1 := zap.String("key1", "value1")
		field2 := zap.Int("key2", 42)
		newLog := log.With(field1, field2)

		assert.NotNil(t, newLog)
		assert.NotSame(t, log, newLog)
	})

	t.Run("Logging methods with plain context", func(t *testing.T) {
		ctx := context.Background()

		assert.NotPanics(t, func() {
			log.Debug(ctx, "debug message")
			log.Info(ctx, "info message")
			log.Warn(ctx, "warning message")
			log.Error(ctx, "error message")
		})
	})

	t.Run("Logging methods with request ID context", func(t *testing.T) {
		requestID := "test-request-id-123"
		ctx := logger.NewRequestIDContext(context.Background(), requestID)

		id, ok := logger.GetRequestID(ctx)
		assert.True(t, ok)
		assert.Equal(t, requestID, id)

		assert.NotPanics(t, func() {
			log.Debug(ctx, "debug message with request ID")
			log.Info(ctx, "info message with request ID")
			log.Warn(ctx, "warning message with request ID")
			log.Error(ctx, "error message with request ID")
		})
	})

	t.Run("Logging methods with custom fields", func(t *testing.T) {
		ctx := context.Background()
		field1 := zap.String("custom_field", "custom_value")
		field2 := zap.Int("count", 100)

		assert.NotPanics(t, func() {
			log.Debug(ctx, "debug with fields", field1, field2)
			log.Info(ctx, "info with fields", field1, field2)
			log.Warn(ctx, "warn with fields", field1, field2)
			log.Error(ctx, "error with fields", field1, field2)
		})
	})

	t.Run("Sync method", func(t *testing.T) {
		assert.NotPanics(t, func() {
			err := log.Sync()
			_ = err
		})
	})

	t.Run("WithRequestID creates logger with request ID", func(t *testing.T) {
		requestID := "test-request-id-456"
		ctx := logger.NewRequestIDContext(context.Background(), requestID)

		newLog := log.WithRequestID(ctx)
		assert.NotNil(t, newLog)
		assert.NotSame(t, log, newLog)
	})
}
