package context_test

import (
	"context"
	"errors"
	"testing"

	"gogetnote/pkg/logger"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestFromContext(t *testing.T) {
	t.Run("success when logger exists in context", func(t *testing.T) {
		testLogger, err := logger.NewLogger(logger.Development, "debug")
		require.NoError(t, err)

		ctx := logger.NewContext(context.Background(), testLogger)

		retrievedLogger, err := logger.FromContext(ctx)
		assert.NoError(t, err)
		assert.Same(t, testLogger, retrievedLogger)
	})

	t.Run("error when no logger in context", func(t *testing.T) {
		ctx := context.Background()

		retrievedLogger, err := logger.FromContext(ctx)
		assert.Error(t, err)
		assert.Nil(t, retrievedLogger)
		assert.True(t, errors.Is(err, logger.ErrLoggerNotFound))
	})

	t.Run("error when context has non-logger values", func(t *testing.T) {
		ctx := context.WithValue(context.Background(), "some-key", "not a logger")

		retrievedLogger, err := logger.FromContext(ctx)
		assert.Error(t, err)
		assert.Nil(t, retrievedLogger)
		assert.True(t, errors.Is(err, logger.ErrLoggerNotFound))
	})

	t.Run("success with derived context", func(t *testing.T) {
		testLogger, err := logger.NewLogger(logger.Development, "debug")
		require.NoError(t, err)

		ctx := logger.NewContext(context.Background(), testLogger)
		derivedCtx := context.WithValue(ctx, "some-key", "some-value")

		retrievedLogger, err := logger.FromContext(derivedCtx)
		assert.NoError(t, err)
		assert.Same(t, testLogger, retrievedLogger)
	})

	t.Run("error with nil context", func(t *testing.T) {
		retrievedLogger, err := logger.FromContext(nil)
		assert.Error(t, err)
		assert.Nil(t, retrievedLogger)
		assert.True(t, errors.Is(err, logger.ErrLoggerNotFound))
	})
}

func TestFromContextWithMultipleLoggers(t *testing.T) {
	logger1, err := logger.NewLogger(logger.Development, "debug")
	require.NoError(t, err)

	logger2, err := logger.NewLogger(logger.Production, "info")
	require.NoError(t, err)

	ctx1 := logger.NewContext(context.Background(), logger1)
	ctx2 := logger.NewContext(context.Background(), logger2)

	retrieved1, err := logger.FromContext(ctx1)
	assert.NoError(t, err)
	assert.Same(t, logger1, retrieved1)

	retrieved2, err := logger.FromContext(ctx2)
	assert.NoError(t, err)
	assert.Same(t, logger2, retrieved2)
}
