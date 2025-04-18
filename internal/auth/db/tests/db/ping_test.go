package db_test

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/undefinedlabs/go-mpatch"

	"gogetnote/internal/auth/config"
	"gogetnote/internal/auth/db"
	"gogetnote/pkg/db/postgres"
	"gogetnote/pkg/logger"
)

func TestPing(t *testing.T) {
	err := logger.InitGlobalLoggerWithLevel(logger.Development, "info")
	require.NoError(t, err)

	ctx := context.Background()

	t.Run("Integration - Ping with real database", func(t *testing.T) {
		migratePatch, err := mpatch.PatchMethod(postgres.MigrateDSN, func(ctx context.Context, dsn, migrationsPath string) error {
			return nil
		})
		require.NoError(t, err)
		defer safeUnpatch(t, migratePatch)

		cfg := &config.PostgresConfig{
			Host:     "localhost",
			Port:     5432,
			User:     "postgres",
			Password: "postgres",
			Database: "postgres",
			MinConn:  1,
			MaxConn:  2,
		}

		database, err := db.New(ctx, cfg, "./migrations")
		if err != nil {
			t.Skip("Skipping test - failed to connect to database:", err)
			return
		}
		defer database.Close(ctx)

		err = database.Ping(ctx)
		assert.NoError(t, err, "Ping should succeed with a working connection")
	})

	t.Run("With unreachable database", func(t *testing.T) {
		migratePatch, err := mpatch.PatchMethod(postgres.MigrateDSN, func(ctx context.Context, dsn, migrationsPath string) error {
			return nil
		})
		require.NoError(t, err)
		defer safeUnpatch(t, migratePatch)

		invalidCfg := &config.PostgresConfig{
			Host:     "nonexistenthost",
			Port:     5432,
			User:     "wrong",
			Password: "wrong",
			Database: "wrongdb",
			MinConn:  1,
			MaxConn:  2,
		}

		database, err := db.New(ctx, invalidCfg, "./migrations")

		assert.Error(t, err, "Connection to unreachable database should fail")
		assert.Nil(t, database, "Database instance should not be created on connection error")
	})

	t.Run("With working connection that is later closed", func(t *testing.T) {
		migratePatch, err := mpatch.PatchMethod(postgres.MigrateDSN, func(ctx context.Context, dsn, migrationsPath string) error {
			return nil
		})
		require.NoError(t, err)
		defer safeUnpatch(t, migratePatch)

		cfg := &config.PostgresConfig{
			Host:     "localhost",
			Port:     5432,
			User:     "postgres",
			Password: "postgres",
			Database: "postgres",
			MinConn:  1,
			MaxConn:  2,
		}

		database, err := db.New(ctx, cfg, "./migrations")
		if err != nil {
			t.Skip("Skipping test - failed to connect to database:", err)
			return
		}

		err = database.Ping(ctx)
		assert.NoError(t, err, "Initial ping should be successful")

		database.Close(ctx)

		err = database.Ping(ctx)
		assert.Error(t, err, "Ping should fail after connection is closed")
	})
}
