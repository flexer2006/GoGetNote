package context_test

import (
	"context"
	"testing"

	"gogetnote/pkg/logger"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestInitGlobalLogger(t *testing.T) {
	logger.SetGlobalLogger(nil)

	t.Run("successfully initializes global logger", func(t *testing.T) {
		logger.SetGlobalLogger(nil)

		err := logger.InitGlobalLogger(logger.Development)
		require.NoError(t, err)

		emptyCtx := context.Background()
		globalLog := logger.Log(emptyCtx)
		assert.NotNil(t, globalLog)
	})

	t.Run("returns nil when global logger already exists", func(t *testing.T) {
		logger.SetGlobalLogger(nil)

		err1 := logger.InitGlobalLogger(logger.Production)
		require.NoError(t, err1)

		emptyCtx := context.Background()
		firstLogger := logger.Log(emptyCtx)
		require.NotNil(t, firstLogger)

		err2 := logger.InitGlobalLogger(logger.Development)
		require.NoError(t, err2)

		secondLogger := logger.Log(emptyCtx)

		assert.Same(t, firstLogger, secondLogger)
	})

	t.Run("returns wrapped error on initialization failure", func(t *testing.T) {
		logger.SetGlobalLogger(nil)

		err := logger.InitGlobalLoggerWithLevel(logger.Development, "debug")
		require.NoError(t, err)
	})
}
