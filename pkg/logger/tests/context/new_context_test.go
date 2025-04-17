package context_test

import (
	"context"
	"testing"

	"gogetnote/pkg/logger"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewContext(t *testing.T) {
	t.Run("adds logger to context and can be retrieved", func(t *testing.T) {
		testLogger, err := logger.NewLogger(logger.Development, "debug")
		require.NoError(t, err)
		require.NotNil(t, testLogger)

		ctx := context.Background()
		loggerCtx := logger.NewContext(ctx, testLogger)

		assert.NotSame(t, ctx, loggerCtx)

		retrievedLogger, err := logger.FromContext(loggerCtx)
		require.NoError(t, err)
		require.NotNil(t, retrievedLogger)

		assert.Same(t, testLogger, retrievedLogger)
	})

	t.Run("calling Log() gets logger from context", func(t *testing.T) {
		testLogger, err := logger.NewLogger(logger.Development, "debug")
		require.NoError(t, err)

		ctx := context.Background()
		loggerCtx := logger.NewContext(ctx, testLogger)

		retrievedLogger := logger.Log(loggerCtx)
		assert.Same(t, testLogger, retrievedLogger)
	})

	t.Run("different loggers in different contexts", func(t *testing.T) {
		logger1, err := logger.NewLogger(logger.Development, "debug")
		require.NoError(t, err)

		logger2, err := logger.NewLogger(logger.Production, "info")
		require.NoError(t, err)

		ctx := context.Background()
		ctx1 := logger.NewContext(ctx, logger1)
		ctx2 := logger.NewContext(ctx, logger2)

		retrieved1, err := logger.FromContext(ctx1)
		require.NoError(t, err)

		retrieved2, err := logger.FromContext(ctx2)
		require.NoError(t, err)

		assert.Same(t, logger1, retrieved1)
		assert.Same(t, logger2, retrieved2)
		assert.NotSame(t, retrieved1, retrieved2)
	})

	t.Run("FromContext returns error for context without logger", func(t *testing.T) {
		ctx := context.Background()

		_, err := logger.FromContext(ctx)

		assert.Error(t, err)
		assert.Contains(t, err.Error(), logger.ErrLoggerNotFound)
	})

	t.Run("context hierarchy maintains logger", func(t *testing.T) {
		testLogger, err := logger.NewLogger(logger.Development, "debug")
		require.NoError(t, err)

		baseCtx := context.Background()
		loggerCtx := logger.NewContext(baseCtx, testLogger)

		childKey := "child-key"
		childValue := "child-value"
		childCtx := context.WithValue(loggerCtx, childKey, childValue)

		retrievedLogger, err := logger.FromContext(childCtx)
		require.NoError(t, err)
		assert.Same(t, testLogger, retrievedLogger)

		assert.Equal(t, childValue, childCtx.Value(childKey))
	})
}
