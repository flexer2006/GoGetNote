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
	migrationsDir := "./migrations"

	t.Run("successful database creation", func(t *testing.T) {
		migratePatch, err := mpatch.PatchMethod(postgres.MigrateDSN, func(ctx context.Context, dsn, migrationsPath string) error {
			assert.Equal(t, cfg.GetConnectionURL(), dsn)
			assert.Contains(t, migrationsPath, "file://")
			return nil
		})
		require.NoError(t, err, "Error patching MigrateDSN")
		defer safeUnpatch(t, migratePatch)

		mockDB := &postgres.Database{}

		newPatch, err := mpatch.PatchMethod(postgres.New, func(ctx context.Context, dsn string, minConn, maxConn int) (*postgres.Database, error) {
			assert.Equal(t, cfg.GetDSN(), dsn)
			assert.Equal(t, cfg.MinConn, minConn)
			assert.Equal(t, cfg.MaxConn, maxConn)
			return mockDB, nil
		})
		require.NoError(t, err, "Error patching postgres.New")
		defer safeUnpatch(t, newPatch)

		database, err := db.New(ctx, cfg, migrationsDir)

		assert.NoError(t, err)
		assert.NotNil(t, database)
		assert.Equal(t, mockDB, database.Database())
	})

	t.Run("migration error", func(t *testing.T) {
		expectedErr := errors.New("migration error")

		migratePatch, err := mpatch.PatchMethod(postgres.MigrateDSN, func(ctx context.Context, dsn, migrationsPath string) error {
			return expectedErr
		})
		require.NoError(t, err, "Error patching MigrateDSN")
		defer safeUnpatch(t, migratePatch)

		database, err := db.New(ctx, cfg, migrationsDir)

		assert.Error(t, err)
		assert.Nil(t, database)
		assert.ErrorContains(t, err, "failed to apply authentication database migrations")
		assert.ErrorIs(t, err, expectedErr)
	})

	t.Run("database connection error", func(t *testing.T) {
		expectedErr := errors.New("connection error")

		migratePatch, err := mpatch.PatchMethod(postgres.MigrateDSN, func(ctx context.Context, dsn, migrationsPath string) error {
			return nil
		})
		require.NoError(t, err, "Error patching MigrateDSN")
		defer safeUnpatch(t, migratePatch)

		newPatch, err := mpatch.PatchMethod(postgres.New, func(ctx context.Context, dsn string, minConn, maxConn int) (*postgres.Database, error) {
			return nil, expectedErr
		})
		require.NoError(t, err, "Error patching postgres.New")
		defer safeUnpatch(t, newPatch)

		database, err := db.New(ctx, cfg, migrationsDir)

		assert.Error(t, err)
		assert.Nil(t, database)
		assert.ErrorContains(t, err, "failed to connect to authentication database")
		assert.ErrorIs(t, err, expectedErr)
	})

	t.Run("absolute path handling", func(t *testing.T) {
		absPath := "/absolute/path/migrations"

		migratePatch, err := mpatch.PatchMethod(postgres.MigrateDSN, func(ctx context.Context, dsn, migrationsPath string) error {
			assert.Equal(t, "file://"+absPath, migrationsPath)
			return nil
		})
		require.NoError(t, err, "Error patching MigrateDSN")
		defer safeUnpatch(t, migratePatch)

		newPatch, err := mpatch.PatchMethod(postgres.New, func(ctx context.Context, dsn string, minConn, maxConn int) (*postgres.Database, error) {
			return &postgres.Database{}, nil
		})
		require.NoError(t, err, "Error patching postgres.New")
		defer safeUnpatch(t, newPatch)

		database, err := db.New(ctx, cfg, absPath)

		assert.NoError(t, err)
		assert.NotNil(t, database)
	})

	t.Run("relative path handling", func(t *testing.T) {
		relPath := "./relative/migrations"

		absPath, err := filepath.Abs(relPath)
		require.NoError(t, err)

		migratePatch, err := mpatch.PatchMethod(postgres.MigrateDSN, func(ctx context.Context, dsn, migrationsPath string) error {
			assert.Equal(t, "file://"+absPath, migrationsPath)
			return nil
		})
		require.NoError(t, err, "Error patching MigrateDSN")
		defer safeUnpatch(t, migratePatch)

		newPatch, err := mpatch.PatchMethod(postgres.New, func(ctx context.Context, dsn string, minConn, maxConn int) (*postgres.Database, error) {
			return &postgres.Database{}, nil
		})
		require.NoError(t, err, "Error patching postgres.New")
		defer safeUnpatch(t, newPatch)

		database, err := db.New(ctx, cfg, relPath)

		assert.NoError(t, err)
		assert.NotNil(t, database)
	})

	t.Run("absolute path error", func(t *testing.T) {
		expectedErr := errors.New("path error")

		absPatch, err := mpatch.PatchMethod(filepath.Abs, func(path string) (string, error) {
			return "", expectedErr
		})
		require.NoError(t, err, "Error patching filepath.Abs")
		defer safeUnpatch(t, absPatch)

		database, err := db.New(ctx, cfg, "./relative/path")

		assert.Error(t, err)
		assert.Nil(t, database)
		assert.ErrorContains(t, err, "failed to get path")
		assert.ErrorIs(t, err, expectedErr)
	})
}
