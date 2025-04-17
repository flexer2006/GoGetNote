package logger_test

import (
	"context"
	"testing"

	"gogetnote/pkg/logger"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewLogger(t *testing.T) {
	t.Run("development environment with different log levels", func(t *testing.T) {
		testCases := []struct {
			level string
			valid bool
		}{
			{"debug", true},
			{"info", true},
			{"warn", true},
			{"warning", true},
			{"error", true},
			{"invalid", true},
			{"", true},
		}

		for _, tc := range testCases {
			t.Run("level="+tc.level, func(t *testing.T) {
				log, err := logger.NewLogger(logger.Development, tc.level)
				if tc.valid {
					require.NoError(t, err)
					require.NotNil(t, log)
				} else {
					require.Error(t, err)
				}
			})
		}
	})

	t.Run("production environment with different log levels", func(t *testing.T) {
		testCases := []struct {
			level string
			valid bool
		}{
			{"debug", true},
			{"info", true},
			{"warn", true},
			{"warning", true},
			{"error", true},
			{"invalid", true},
			{"", true},
		}

		for _, tc := range testCases {
			t.Run("level="+tc.level, func(t *testing.T) {
				log, err := logger.NewLogger(logger.Production, tc.level)
				if tc.valid {
					require.NoError(t, err)
					require.NotNil(t, log)
				} else {
					require.Error(t, err)
				}
			})
		}
	})

	t.Run("basic logging functionality", func(t *testing.T) {
		log, err := logger.NewLogger(logger.Development, "info")
		require.NoError(t, err)
		require.NotNil(t, log)

		ctx := logger.NewRequestIDContext(context.Background(), "test-request-id")

		assert.NotPanics(t, func() {
			log.Debug(ctx, "debug message")
			log.Info(ctx, "info message")
			log.Warn(ctx, "warn message")
			log.Error(ctx, "error message")
		})
	})

	t.Run("with method creates new logger instance", func(t *testing.T) {
		log, err := logger.NewLogger(logger.Development, "info")
		require.NoError(t, err)

		newLog := log.With()
		assert.NotNil(t, newLog)
		assert.NotSame(t, log, newLog)
	})
}
