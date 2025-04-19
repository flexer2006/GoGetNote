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

const (
	MsgSkipTest                 = "skipping test - failed to connect to database:"
	MsgPingShouldSucceed        = "ping should succeed with a working connection"
	MsgConnectionShouldFail     = "connection to unreachable database should fail"
	MsgInstanceNotCreated       = "database instance should not be created on connection error"
	MsgPingShouldFailAfterClose = "ping should fail after connection is closed"
	MsgInitialPingShouldSucceed = "initial ping should be successful"
	DefaultMigrationsPath       = "./migrations"
)

func TestPing(t *testing.T) {
	err := logger.InitGlobalLoggerWithLevel(logger.Development, "info")
	require.NoError(t, err)

	ctx := context.Background()

	t.Run("integration - Ping with real database", func(t *testing.T) {
		migratePatch, err := mpatch.PatchMethod(postgres.MigrateDSN, func(_ context.Context, _, _ string) error {
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

		database, err := db.New(ctx, cfg, DefaultMigrationsPath)
		if err != nil {
			t.Skip(MsgSkipTest, err)
			return
		}
		defer database.Close(ctx)

		err = database.Ping(ctx)
		assert.NoError(t, err, MsgPingShouldSucceed)
	})

	t.Run("with unreachable database", func(t *testing.T) {
		migratePatch, err := mpatch.PatchMethod(postgres.MigrateDSN, func(_ context.Context, _, _ string) error {
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

		database, err := db.New(ctx, invalidCfg, DefaultMigrationsPath)

		require.Error(t, err, MsgConnectionShouldFail)
		assert.Nil(t, database, MsgInstanceNotCreated)
	})

	t.Run("with working connection that is later closed", func(t *testing.T) {
		migratePatch, err := mpatch.PatchMethod(postgres.MigrateDSN, func(_ context.Context, _, _ string) error {
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

		database, err := db.New(ctx, cfg, DefaultMigrationsPath)
		if err != nil {
			t.Skip(MsgSkipTest, err)
			return
		}

		err = database.Ping(ctx)
		require.NoError(t, err, MsgInitialPingShouldSucceed)

		database.Close(ctx)

		err = database.Ping(ctx)
		assert.Error(t, err, MsgPingShouldFailAfterClose)
	})
}
