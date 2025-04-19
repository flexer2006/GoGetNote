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

const (
	ErrUnpatchMsg        = "failed to unpatch"
	ErrUnpatchCloseMsg   = "failed to unpatch Close method"
	ErrPatchCloseMsg     = "error patching Close method"
	CloseMethodCalledMsg = "close method should be called"
	MigrationsPath       = "./migrations"
)

func safeUnpatch(t *testing.T, p *mpatch.Patch) {
	t.Helper()
	if err := p.Unpatch(); err != nil {
		t.Errorf("%s: %v", ErrUnpatchMsg, err)
	}
}

func TestClose(t *testing.T) {
	err := logger.InitGlobalLoggerWithLevel(logger.Development, "info")
	require.NoError(t, err)

	ctx := context.Background()

	t.Run("сlose should call Close on the internal database", func(t *testing.T) {
		closeCalled := false

		patch, err := mpatch.PatchInstanceMethodByName(reflect.TypeOf(&postgres.Database{}), "Close", func(_ *postgres.Database, _ context.Context) {
			closeCalled = true
		})
		require.NoError(t, err, ErrPatchCloseMsg)
		defer func() {
			if err := patch.Unpatch(); err != nil {
				t.Errorf("%s: %v", ErrUnpatchCloseMsg, err)
			}
		}()

		cfg := &config.PostgresConfig{
			Host:     "testhost",
			Port:     5432,
			User:     "testuser",
			Password: "testpass",
			Database: "testdb",
			MinConn:  1,
			MaxConn:  10,
		}

		migratePatch, err := mpatch.PatchMethod(postgres.MigrateDSN, func(_ context.Context, _, _ string) error {
			return nil
		})
		require.NoError(t, err)
		defer safeUnpatch(t, migratePatch)

		newPatch, err := mpatch.PatchMethod(postgres.New, func(_ context.Context, _ string, _, _ int) (*postgres.Database, error) {
			return &postgres.Database{}, nil
		})
		require.NoError(t, err)
		defer safeUnpatch(t, newPatch)

		database, err := db.New(ctx, cfg, MigrationsPath)
		require.NoError(t, err)

		database.Close(ctx)

		require.True(t, closeCalled, CloseMethodCalledMsg)
	})

	t.Run("close should not panic", func(t *testing.T) {
		patch, err := mpatch.PatchInstanceMethodByName(reflect.TypeOf(&postgres.Database{}), "Close", func(_ *postgres.Database, _ context.Context) {
		})
		require.NoError(t, err)
		defer safeUnpatch(t, patch)

		cfg := &config.PostgresConfig{
			Host:     "testhost",
			Port:     5432,
			User:     "testuser",
			Password: "testpass",
			Database: "testdb",
			MinConn:  1,
			MaxConn:  10,
		}

		migratePatch, err := mpatch.PatchMethod(postgres.MigrateDSN, func(_ context.Context, _, _ string) error {
			return nil
		})
		require.NoError(t, err)
		defer safeUnpatch(t, migratePatch)

		newPatch, err := mpatch.PatchMethod(postgres.New, func(_ context.Context, _ string, _, _ int) (*postgres.Database, error) {
			return &postgres.Database{}, nil
		})
		require.NoError(t, err)
		defer safeUnpatch(t, newPatch)

		database, err := db.New(ctx, cfg, MigrationsPath)
		require.NoError(t, err)

		require.NotPanics(t, func() {
			database.Close(ctx)
		})
	})
}
