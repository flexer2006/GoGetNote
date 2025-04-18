package context_test

import (
	"context"
	"testing"

	"gogetnote/pkg/logger"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLog(t *testing.T) {
	logger.SetGlobalLogger(nil)
	defer logger.SetGlobalLogger(nil)

	t.Run("returns logger from context when available", func(t *testing.T) {
		contextLogger, err := logger.NewLogger(logger.Development, "debug")
		require.NoError(t, err)

		globalLogger, err := logger.NewLogger(logger.Production, "error")
		require.NoError(t, err)
		logger.SetGlobalLogger(globalLogger)

		ctx := logger.NewContext(context.Background(), contextLogger)

		result := logger.Log(ctx)
		assert.Same(t, contextLogger, result)
		assert.NotSame(t, globalLogger, result)
	})

	t.Run("returns global logger when no logger in context", func(t *testing.T) {
		globalLogger, err := logger.NewLogger(logger.Development, "info")
		require.NoError(t, err)
		logger.SetGlobalLogger(globalLogger)

		ctx := context.Background()

		result := logger.Log(ctx)
		assert.Same(t, globalLogger, result)
	})

	t.Run("returns fallback logger when no context or global logger", func(t *testing.T) {
		logger.SetGlobalLogger(nil)

		ctx := context.Background()

		result := logger.Log(ctx)
		assert.NotNil(t, result, "fallback logger should not be nil")

		newLogger, err := logger.NewLogger(logger.Development, "debug")
		require.NoError(t, err)
		assert.NotSame(t, newLogger, result, "should not be a newly created logger")
	})

	t.Run("handles empty context by returning global or fallback logger", func(t *testing.T) {
		globalLogger, err := logger.NewLogger(logger.Production, "warn")
		require.NoError(t, err)
		logger.SetGlobalLogger(globalLogger)

		emptyCtx := context.Background()
		result := logger.Log(emptyCtx)
		assert.NotNil(t, result)
		assert.Same(t, globalLogger, result)

		logger.SetGlobalLogger(nil)
		result = logger.Log(emptyCtx)
		assert.NotNil(t, result, "should return fallback logger with empty context and no global logger")
	})

	t.Run("returns the same fallback logger instance each time", func(t *testing.T) {
		logger.SetGlobalLogger(nil)

		ctx := context.Background()
		result1 := logger.Log(ctx)
		result2 := logger.Log(ctx)

		assert.Same(t, result1, result2, "fallback logger should be a singleton")
	})
}
