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

const (
	AuthPostgresHost = "AUTH_POSTGRES_HOST"
	AuthPostgresPort = "AUTH_POSTGRES_PORT"
	AuthPostgresUser = "AUTH_POSTGRES_USER"
	//nolint:gosec
	AuthPostgresPassword = "AUTH_POSTGRES_PASSWORD"
	AuthPostgresDB       = "AUTH_POSTGRES_DB"
	AuthPostgresMinConn  = "AUTH_POSTGRES_MIN_CONN"
	AuthPostgresMaxConn  = "AUTH_POSTGRES_MAX_CONN"

	AuthLoggerLevel = "AUTH_LOGGER_LEVEL"
	AuthLoggerMode  = "AUTH_LOGGER_MODE"

	AuthShutdownTimeout = "AUTH_GRACEFUL_SHUTDOWN_TIMEOUT"

	//nolint:gosec
	ExpectedPostgresDSN = "host=customhost port=5433 user=dbuser password=dbpass dbname=customdb sslmode=disable"
	//nolint:gosec
	ExpectedPostgresConnectURL = "postgres://dbuser:dbpass@customhost:5433/customdb?sslmode=disable"
)

func TestLoad(t *testing.T) {
	err := logger.InitGlobalLoggerWithLevel(logger.Development, "info")
	require.NoError(t, err)

	ctx := context.Background()

	t.Run("successfully loads config from environment", func(t *testing.T) {
		envVars := map[string]string{
			AuthPostgresHost:     "testhost",
			AuthPostgresPort:     "5555",
			AuthPostgresUser:     "testuser",
			AuthPostgresPassword: "testpass",
			AuthPostgresDB:       "testdb",
			AuthPostgresMinConn:  "3",
			AuthPostgresMaxConn:  "20",
			AuthLoggerLevel:      "debug",
			AuthLoggerMode:       "production",
			AuthShutdownTimeout:  "10",
		}

		for k, v := range envVars {
			require.NoError(t, os.Setenv(k, v))
		}

		defer func() {
			for k := range envVars {
				require.NoError(t, os.Unsetenv(k))
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
			AuthPostgresHost, AuthPostgresPort, AuthPostgresUser,
			AuthPostgresPassword, AuthPostgresDB, AuthPostgresMinConn,
			AuthPostgresMaxConn, AuthLoggerLevel, AuthLoggerMode,
			AuthShutdownTimeout,
		}
		for _, env := range envVars {
			require.NoError(t, os.Unsetenv(env))
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
		require.NoError(t, os.Setenv(AuthPostgresPort, "not_a_number"))
		defer func() {
			require.NoError(t, os.Unsetenv(AuthPostgresPort))
		}()

		cfg, err := config.Load(ctx)

		require.Error(t, err)
		assert.Contains(t, err.Error(), "invalid syntax")
		assert.Nil(t, cfg)
	})

	t.Run("verifies DSN generation", func(t *testing.T) {
		require.NoError(t, os.Setenv(AuthPostgresHost, "customhost"))
		require.NoError(t, os.Setenv(AuthPostgresPort, "5433"))
		require.NoError(t, os.Setenv(AuthPostgresUser, "dbuser"))
		require.NoError(t, os.Setenv(AuthPostgresPassword, "dbpass"))
		require.NoError(t, os.Setenv(AuthPostgresDB, "customdb"))
		defer func() {
			require.NoError(t, os.Unsetenv(AuthPostgresHost))
			require.NoError(t, os.Unsetenv(AuthPostgresPort))
			require.NoError(t, os.Unsetenv(AuthPostgresUser))
			require.NoError(t, os.Unsetenv(AuthPostgresPassword))
			require.NoError(t, os.Unsetenv(AuthPostgresDB))
		}()

		cfg, err := config.Load(ctx)
		require.NoError(t, err)
		require.NotNil(t, cfg)

		assert.Equal(t, ExpectedPostgresDSN, cfg.Postgres.GetDSN())
		assert.Equal(t, ExpectedPostgresConnectURL, cfg.Postgres.GetConnectionURL())
	})
}
