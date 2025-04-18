package context_test

import (
	"context"
	"gogetnote/pkg/logger"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestInitGlobalLoggerWithLevel(t *testing.T) {
	logger.SetGlobalLogger(nil)

	t.Run("successfully initializes global logger with specific level", func(t *testing.T) {
		logger.SetGlobalLogger(nil)

		err := logger.InitGlobalLoggerWithLevel(logger.Development, "debug")
		require.NoError(t, err)

		emptyCtx := context.Background()
		globalLog := logger.Log(emptyCtx)
		assert.NotNil(t, globalLog)
	})

	t.Run("returns nil when global logger already exists", func(t *testing.T) {
		logger.SetGlobalLogger(nil)

		err1 := logger.InitGlobalLoggerWithLevel(logger.Production, "info")
		require.NoError(t, err1)

		emptyCtx := context.Background()
		firstLogger := logger.Log(emptyCtx)
		require.NotNil(t, firstLogger)

		err2 := logger.InitGlobalLoggerWithLevel(logger.Development, "debug")
		require.NoError(t, err2)

		secondLogger := logger.Log(emptyCtx)

		assert.Same(t, firstLogger, secondLogger)
	})
}
