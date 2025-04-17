package config_test

import (
	"context"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"gogetnote/internal/auth/config"
	"gogetnote/pkg/logger"
)

func TestLoad(t *testing.T) {
	err := logger.InitGlobalLoggerWithLevel(logger.Development, "info")
	require.NoError(t, err)

	ctx := context.Background()

	t.Run("successfully loads config from environment", func(t *testing.T) {
		envVars := map[string]string{
			"AUTH_POSTGRES_HOST":             "testhost",
			"AUTH_POSTGRES_PORT":             "5555",
			"AUTH_POSTGRES_USER":             "testuser",
			"AUTH_POSTGRES_PASSWORD":         "testpass",
			"AUTH_POSTGRES_DB":               "testdb",
			"AUTH_POSTGRES_MIN_CONN":         "3",
			"AUTH_POSTGRES_MAX_CONN":         "20",
			"AUTH_LOGGER_LEVEL":              "debug",
			"AUTH_LOGGER_MODE":               "production",
			"AUTH_GRACEFUL_SHUTDOWN_TIMEOUT": "10",
		}

		for k, v := range envVars {
			os.Setenv(k, v)
		}

		defer func() {
			for k := range envVars {
				os.Unsetenv(k)
			}
		}()

		cfg, err := config.Load(ctx)

		require.NoError(t, err)
		require.NotNil(t, cfg)

		assert.Equal(t, "testhost", cfg.Postgres.Host)
		assert.Equal(t, 5555, cfg.Postgres.Port)
		assert.Equal(t, "testuser", cfg.Postgres.User)
		assert.Equal(t, "testpass", cfg.Postgres.Password)
		assert.Equal(t, "testdb", cfg.Postgres.Database)
		assert.Equal(t, 3, cfg.Postgres.MinConn)
		assert.Equal(t, 20, cfg.Postgres.MaxConn)

		assert.Equal(t, "debug", cfg.Logging.Level)
		assert.Equal(t, "production", cfg.Logging.Mode)
		assert.Equal(t, logger.Production, cfg.Logging.GetEnvironment())

		assert.Equal(t, 10, cfg.Shutdown.Timeout)
	})

	t.Run("uses default values when environment variables not set", func(t *testing.T) {
		envVars := []string{
			"AUTH_POSTGRES_HOST", "AUTH_POSTGRES_PORT", "AUTH_POSTGRES_USER",
			"AUTH_POSTGRES_PASSWORD", "AUTH_POSTGRES_DB", "AUTH_POSTGRES_MIN_CONN",
			"AUTH_POSTGRES_MAX_CONN", "AUTH_LOGGER_LEVEL", "AUTH_LOGGER_MODE",
			"AUTH_GRACEFUL_SHUTDOWN_TIMEOUT",
		}
		for _, env := range envVars {
			os.Unsetenv(env)
		}

		cfg, err := config.Load(ctx)

		require.NoError(t, err)
		require.NotNil(t, cfg)

		assert.Equal(t, "localhost", cfg.Postgres.Host)
		assert.Equal(t, 5432, cfg.Postgres.Port)
		assert.Equal(t, "postgres", cfg.Postgres.User)
		assert.Equal(t, "postgres", cfg.Postgres.Password)
		assert.Equal(t, "auth", cfg.Postgres.Database)
		assert.Equal(t, 1, cfg.Postgres.MinConn)
		assert.Equal(t, 10, cfg.Postgres.MaxConn)

		assert.Equal(t, "info", cfg.Logging.Level)
		assert.Equal(t, "development", cfg.Logging.Mode)
		assert.Equal(t, logger.Development, cfg.Logging.GetEnvironment())

		assert.Equal(t, 5, cfg.Shutdown.Timeout)
	})

	t.Run("handles error with invalid environment variable", func(t *testing.T) {
		os.Setenv("AUTH_POSTGRES_PORT", "not_a_number")
		defer os.Unsetenv("AUTH_POSTGRES_PORT")

		cfg, err := config.Load(ctx)

		assert.Error(t, err)
		assert.Contains(t, err.Error(), "invalid syntax")
		assert.Nil(t, cfg)
	})

	t.Run("verifies DSN generation", func(t *testing.T) {
		os.Setenv("AUTH_POSTGRES_HOST", "customhost")
		os.Setenv("AUTH_POSTGRES_PORT", "5433")
		os.Setenv("AUTH_POSTGRES_USER", "dbuser")
		os.Setenv("AUTH_POSTGRES_PASSWORD", "dbpass")
		os.Setenv("AUTH_POSTGRES_DB", "customdb")
		defer func() {
			os.Unsetenv("AUTH_POSTGRES_HOST")
			os.Unsetenv("AUTH_POSTGRES_PORT")
			os.Unsetenv("AUTH_POSTGRES_USER")
			os.Unsetenv("AUTH_POSTGRES_PASSWORD")
			os.Unsetenv("AUTH_POSTGRES_DB")
		}()

		cfg, err := config.Load(ctx)
		require.NoError(t, err)
		require.NotNil(t, cfg)

		expectedDSN := "host=customhost port=5433 user=dbuser password=dbpass dbname=customdb sslmode=disable"
		assert.Equal(t, expectedDSN, cfg.Postgres.GetDSN())

		expectedURL := "postgres://dbuser:dbpass@customhost:5433/customdb?sslmode=disable"
		assert.Equal(t, expectedURL, cfg.Postgres.GetConnectionURL())
	})
}
