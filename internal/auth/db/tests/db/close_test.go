package db_test

import (
	"context"
	"reflect"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/undefinedlabs/go-mpatch"

	"gogetnote/internal/auth/config"
	"gogetnote/internal/auth/db"
	"gogetnote/pkg/db/postgres"
	"gogetnote/pkg/logger"
)

func TestClose(t *testing.T) {
	err := logger.InitGlobalLoggerWithLevel(logger.Development, "info")
	require.NoError(t, err)

	ctx := context.Background()

	t.Run("Close should call Close on the internal database", func(t *testing.T) {
		closeCalled := false

		patch, err := mpatch.PatchInstanceMethodByName(reflect.TypeOf(&postgres.Database{}), "Close", func(db *postgres.Database, ctx context.Context) {
			closeCalled = true
		})
		require.NoError(t, err, "Error patching Close method")
		defer patch.Unpatch()

		cfg := &config.PostgresConfig{
			Host:     "testhost",
			Port:     5432,
			User:     "testuser",
			Password: "testpass",
			Database: "testdb",
			MinConn:  1,
			MaxConn:  10,
		}

		migratePatch, err := mpatch.PatchMethod(postgres.MigrateDSN, func(ctx context.Context, dsn, migrationsPath string) error {
			return nil
		})
		require.NoError(t, err)
		defer migratePatch.Unpatch()

		newPatch, err := mpatch.PatchMethod(postgres.New, func(ctx context.Context, dsn string, minConn, maxConn int) (*postgres.Database, error) {
			return &postgres.Database{}, nil
		})
		require.NoError(t, err)
		defer newPatch.Unpatch()

		database, err := db.New(ctx, cfg, "./migrations")
		require.NoError(t, err)

		database.Close(ctx)

		require.True(t, closeCalled, "Close method should be called")
	})

	t.Run("Close should not panic", func(t *testing.T) {
		patch, err := mpatch.PatchInstanceMethodByName(reflect.TypeOf(&postgres.Database{}), "Close", func(db *postgres.Database, ctx context.Context) {
		})
		require.NoError(t, err)
		defer patch.Unpatch()

		cfg := &config.PostgresConfig{
			Host:     "testhost",
			Port:     5432,
			User:     "testuser",
			Password: "testpass",
			Database: "testdb",
			MinConn:  1,
			MaxConn:  10,
		}

		migratePatch, err := mpatch.PatchMethod(postgres.MigrateDSN, func(ctx context.Context, dsn, migrationsPath string) error {
			return nil
		})
		require.NoError(t, err)
		defer migratePatch.Unpatch()

		newPatch, err := mpatch.PatchMethod(postgres.New, func(ctx context.Context, dsn string, minConn, maxConn int) (*postgres.Database, error) {
			return &postgres.Database{}, nil
		})
		require.NoError(t, err)
		defer newPatch.Unpatch()

		database, err := db.New(ctx, cfg, "./migrations")
		require.NoError(t, err)

		require.NotPanics(t, func() {
			database.Close(ctx)
		})
	})
}
