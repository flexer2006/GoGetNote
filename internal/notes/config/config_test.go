package config_test

import (
	"context"
	"gogetnote/internal/notes/config"
	"gogetnote/pkg/logger"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	NotesPostgresHost = "NOTES_POSTGRES_HOST"
	NotesPostgresPort = "NOTES_POSTGRES_PORT"
	NotesPostgresUser = "NOTES_POSTGRES_USER"
	//nolint:gosec
	NotesPostgresPassword = "NOTES_POSTGRES_PASSWORD"
	NotesPostgresDB       = "NOTES_POSTGRES_DB"
	NotesPostgresMinConn  = "NOTES_POSTGRES_MIN_CONN"
	NotesPostgresMaxConn  = "NOTES_POSTGRES_MAX_CONN"

	NotesLoggerLevel = "NOTES_LOGGER_LEVEL"
	NotesLoggerMode  = "NOTES_LOGGER_MODE"

	NotesShutdownTimeout = "NOTES_GRACEFUL_SHUTDOWN_TIMEOUT"

	NotesGRPCPort = "NOTES_GRPC_PORT"

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
			NotesPostgresHost:     "testhost",
			NotesPostgresPort:     "5555",
			NotesPostgresUser:     "testuser",
			NotesPostgresPassword: "testpass",
			NotesPostgresDB:       "testdb",
			NotesPostgresMinConn:  "3",
			NotesPostgresMaxConn:  "20",
			NotesLoggerLevel:      "debug",
			NotesLoggerMode:       "production",
			NotesShutdownTimeout:  "10",
			NotesGRPCPort:         "9090",
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

		assert.Equal(t, 9090, cfg.GRPC.Port)

	})

	t.Run("uses default values when environment variables not set", func(t *testing.T) {
		envVars := []string{
			NotesPostgresHost, NotesPostgresPort, NotesPostgresUser,
			NotesPostgresPassword, NotesPostgresDB, NotesPostgresMinConn,
			NotesPostgresMaxConn, NotesLoggerLevel, NotesLoggerMode,
			NotesShutdownTimeout, NotesGRPCPort,
		}
		for _, env := range envVars {
			require.NoError(t, os.Unsetenv(env))
		}

		cfg, err := config.Load(ctx)

		require.NoError(t, err)
		require.NotNil(t, cfg)

		assert.Equal(t, "0.0.0.0", cfg.Postgres.Host)
		assert.Equal(t, 5433, cfg.Postgres.Port)
		assert.Equal(t, "postgres", cfg.Postgres.User)
		assert.Equal(t, "postgres", cfg.Postgres.Password)
		assert.Equal(t, "notes", cfg.Postgres.Database)
		assert.Equal(t, 1, cfg.Postgres.MinConn)
		assert.Equal(t, 10, cfg.Postgres.MaxConn)

		assert.Equal(t, "info", cfg.Logging.Level)
		assert.Equal(t, "development", cfg.Logging.Mode)
		assert.Equal(t, logger.Development, cfg.Logging.GetEnvironment())

		assert.Equal(t, 5, cfg.Shutdown.Timeout)

		assert.Equal(t, 50053, cfg.GRPC.Port)

	})

	t.Run("handles error with invalid environment variable", func(t *testing.T) {
		require.NoError(t, os.Setenv(NotesPostgresPort, "not_a_number"))
		defer func() {
			require.NoError(t, os.Unsetenv(NotesPostgresPort))
		}()

		cfg, err := config.Load(ctx)

		require.Error(t, err)
		assert.Contains(t, err.Error(), "invalid syntax")
		assert.Nil(t, cfg)
	})

	t.Run("verifies DSN generation", func(t *testing.T) {
		require.NoError(t, os.Setenv(NotesPostgresHost, "customhost"))
		require.NoError(t, os.Setenv(NotesPostgresPort, "5433"))
		require.NoError(t, os.Setenv(NotesPostgresUser, "dbuser"))
		require.NoError(t, os.Setenv(NotesPostgresPassword, "dbpass"))
		require.NoError(t, os.Setenv(NotesPostgresDB, "customdb"))
		defer func() {
			require.NoError(t, os.Unsetenv(NotesPostgresHost))
			require.NoError(t, os.Unsetenv(NotesPostgresPort))
			require.NoError(t, os.Unsetenv(NotesPostgresUser))
			require.NoError(t, os.Unsetenv(NotesPostgresPassword))
			require.NoError(t, os.Unsetenv(NotesPostgresDB))
		}()

		cfg, err := config.Load(ctx)
		require.NoError(t, err)
		require.NotNil(t, cfg)

		assert.Equal(t, ExpectedPostgresDSN, cfg.Postgres.GetDSN())
		assert.Equal(t, ExpectedPostgresConnectURL, cfg.Postgres.GetConnectionURL())
	})
}
