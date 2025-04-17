package request_id_test

import (
	"context"
	"testing"

	"gogetnote/pkg/logger"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

func TestWithRequestID(t *testing.T) {
	t.Run("adds request ID field when present in context", func(t *testing.T) {
		baseLogger, err := logger.NewLogger(logger.Development, "debug")
		require.NoError(t, err)

		requestID := "test-request-id-123"
		ctx := logger.NewRequestIDContext(context.Background(), requestID)

		loggerWithID := baseLogger.WithRequestID(ctx)

		assert.NotSame(t, baseLogger, loggerWithID, "WithRequestID should return a new logger when request ID exists")

		loggerWithID.Info(ctx, "test message with request ID")

		emptyCtx := context.Background()
		loggerWithoutID := baseLogger.WithRequestID(emptyCtx)

		assert.Same(t, baseLogger, loggerWithoutID, "WithRequestID should return the same logger when no request ID exists")
	})

	t.Run("returns original logger when no request ID in context", func(t *testing.T) {
		baseLogger, err := logger.NewLogger(logger.Development, "debug")
		require.NoError(t, err)

		ctx := context.Background()

		resultLogger := baseLogger.WithRequestID(ctx)

		assert.Same(t, baseLogger, resultLogger, "WithRequestID should return the same logger when no request ID exists")
	})

	t.Run("preserves existing fields when adding request ID", func(t *testing.T) {
		baseLogger, err := logger.NewLogger(logger.Development, "debug")
		require.NoError(t, err)

		customField := "custom-field"
		customValue := "custom-value"
		loggerWithField := baseLogger.With(zap.String(customField, customValue))

		requestID := "test-request-id-456"
		ctx := logger.NewRequestIDContext(context.Background(), requestID)

		loggerWithRequestID := loggerWithField.WithRequestID(ctx)

		assert.NotSame(t, loggerWithField, loggerWithRequestID, "WithRequestID should return a new logger")

		loggerWithRequestID.Info(ctx, "test message with both fields")

	})

	t.Run("handles nil context safely", func(t *testing.T) {
		baseLogger, err := logger.NewLogger(logger.Development, "debug")
		require.NoError(t, err)

		ctx := context.Background()

		resultLogger := baseLogger.WithRequestID(ctx)

		assert.Same(t, baseLogger, resultLogger, "WithRequestID should return the same logger for empty context")
	})

	t.Run("request ID field has the expected name", func(t *testing.T) {
		baseLogger, err := logger.NewLogger(logger.Development, "debug")
		require.NoError(t, err)

		requestID := "test-request-id-789"
		ctx := logger.NewRequestIDContext(context.Background(), requestID)

		loggerWithRequestID := baseLogger.WithRequestID(ctx)

		loggerWithRequestID.Info(ctx, "test message for field name")

		assert.NotSame(t, baseLogger, loggerWithRequestID, "WithRequestID should return a new logger for context with ID")
	})
}
