package db_test

import (
	"context"
	"errors"
	"path/filepath"
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
	errMsgMigrate      = "error patching MigrateDSN"
	errMsgMigration    = "failed to apply authentication database migrations"
	errMsgConnection   = "failed to connect to authentication database"
	errMsgRelativePath = "./relative/path"
	errMsgPath         = "failed to get path"
	errMsgPatchNew     = "error patching postgres.New"
	errMsgPatchAbs     = "error patching filepath.Abs"
	migrationsPath     = "./migrations"
)

var (
	errMigration  = errors.New("migration error")
	errConnection = errors.New("connection error")
	errPath       = errors.New("path error")
)

func TestNew(t *testing.T) {
	err := logger.InitGlobalLoggerWithLevel(logger.Development, "info")
	require.NoError(t, err)

	ctx := context.Background()

	cfg := &config.PostgresConfig{
		Host:     "testhost",
		Port:     5432,
		User:     "testuser",
		Password: "testpass",
		Database: "testdb",
		MinConn:  1,
		MaxConn:  10,
	}
	migrationsDir := migrationsPath

	t.Run("successful database creation", func(_ *testing.T) {
	})

	t.Run("migration error", func(t *testing.T) {
		expectedErr := errMigration

		migratePatch, err := mpatch.PatchMethod(postgres.MigrateDSN, func(_ context.Context, _, _ string) error {
			return expectedErr
		})
		require.NoError(t, err, errMsgMigrate)
		defer safeUnpatch(t, migratePatch)

		database, err := db.New(ctx, cfg, migrationsDir)

		require.Error(t, err)
		assert.Nil(t, database)
		require.ErrorContains(t, err, errMsgMigration)
		assert.ErrorIs(t, err, expectedErr)
	})

	t.Run("database connection error", func(t *testing.T) {
		expectedErr := errConnection

		migratePatch, err := mpatch.PatchMethod(postgres.MigrateDSN, func(_ context.Context, _, _ string) error {
			return nil
		})
		require.NoError(t, err, errMsgMigrate)
		defer safeUnpatch(t, migratePatch)

		newPatch, err := mpatch.PatchMethod(postgres.New, func(_ context.Context, _ string, _, _ int) (*postgres.Database, error) {
			return nil, expectedErr
		})
		require.NoError(t, err, errMsgPatchNew)
		defer safeUnpatch(t, newPatch)

		database, err := db.New(ctx, cfg, migrationsDir)

		require.Error(t, err)
		assert.Nil(t, database)
		require.ErrorContains(t, err, errMsgConnection)
		assert.ErrorIs(t, err, expectedErr)
	})

	t.Run("absolute path error", func(t *testing.T) {
		expectedErr := errPath

		absPatch, err := mpatch.PatchMethod(filepath.Abs, func(_ string) (string, error) {
			return "", expectedErr
		})
		require.NoError(t, err, errMsgPatchAbs)
		defer safeUnpatch(t, absPatch)

		database, err := db.New(ctx, cfg, errMsgRelativePath)

		require.Error(t, err)
		assert.Nil(t, database)
		require.ErrorContains(t, err, errMsgPath)
		assert.ErrorIs(t, err, expectedErr)
	})
}
