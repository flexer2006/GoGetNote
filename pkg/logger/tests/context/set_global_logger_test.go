package context_test

import (
	"context"
	"testing"

	"gogetnote/pkg/logger"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSetGlobalLogger(t *testing.T) {
	emptyCtx := context.Background()

	t.Run("sets global logger to a new value", func(t *testing.T) {
		testLogger, err := logger.NewLogger(logger.Development, "debug")
		require.NoError(t, err)

		logger.SetGlobalLogger(testLogger)

		returnedLogger := logger.Log(emptyCtx)
		assert.Same(t, testLogger, returnedLogger, "Log() should return the global logger we just set")
	})

	t.Run("sets global logger to nil", func(t *testing.T) {
		testLogger, err := logger.NewLogger(logger.Development, "debug")
		require.NoError(t, err)
		logger.SetGlobalLogger(testLogger)

		logger.SetGlobalLogger(nil)

		returnedLogger := logger.Log(emptyCtx)
		assert.NotNil(t, returnedLogger, "Log() should return the fallback logger, not nil")
		assert.NotSame(t, testLogger, returnedLogger, "Log() should not return previous global logger")
	})

	t.Run("logger from context has priority over global logger", func(t *testing.T) {
		globalLogger, err := logger.NewLogger(logger.Production, "info")
		require.NoError(t, err)
		logger.SetGlobalLogger(globalLogger)

		contextLogger, err := logger.NewLogger(logger.Development, "debug")
		require.NoError(t, err)

		ctx := logger.NewContext(emptyCtx, contextLogger)

		returnedLogger := logger.Log(ctx)
		assert.Same(t, contextLogger, returnedLogger, "Log() should return the context logger")
		assert.NotSame(t, globalLogger, returnedLogger, "Log() should not return the global logger")
	})

	t.Run("multiple calls update the global logger", func(t *testing.T) {
		logger1, err := logger.NewLogger(logger.Development, "debug")
		require.NoError(t, err)
		logger.SetGlobalLogger(logger1)

		returnedLogger := logger.Log(emptyCtx)
		assert.Same(t, logger1, returnedLogger)

		logger2, err := logger.NewLogger(logger.Production, "info")
		require.NoError(t, err)
		logger.SetGlobalLogger(logger2)

		returnedLogger = logger.Log(emptyCtx)
		assert.Same(t, logger2, returnedLogger)
		assert.NotSame(t, logger1, returnedLogger)
	})

	logger.SetGlobalLogger(nil)
}
