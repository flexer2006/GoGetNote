package migrate_test

import (
	"context"
	"errors"
	"testing"

	"github.com/golang-migrate/migrate/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"gogetnote/pkg/db/postgres"
	"gogetnote/pkg/logger"

	"github.com/undefinedlabs/go-mpatch"
)

// Вспомогательная функция для безопасной отмены патча
func safeUnpatch(t *testing.T, p *mpatch.Patch) {
	if err := p.Unpatch(); err != nil {
		t.Errorf("Failed to unpatch: %v", err)
	}
}

func TestMigrateDSN(t *testing.T) {
	err := logger.InitGlobalLoggerWithLevel(logger.Development, "info")
	require.NoError(t, err)

	ctx := context.Background()
	dsn := "postgres://user:pass@localhost:5432/testdb"
	migrationsPath := "file://./migrations"

	t.Run("success case", func(t *testing.T) {
		newPatch, err := mpatch.PatchMethod(migrate.New, func(source, database string) (*migrate.Migrate, error) {
			assert.Equal(t, migrationsPath, source)
			assert.Equal(t, dsn, database)

			return nil, nil
		})
		require.NoError(t, err, "Failed to patch migrate.New")
		defer func() {
			if err := newPatch.Unpatch(); err != nil {
				t.Errorf("Failed to unpatch: %v", err)
			}
		}()

		upCalled := false
		upPatch, err := mpatch.PatchMethod((*migrate.Migrate).Up, func(_ *migrate.Migrate) error {
			upCalled = true
			return nil
		})
		require.NoError(t, err, "Failed to patch Up method")
		defer safeUnpatch(t, upPatch)

		closeCalled := false
		closePatch, err := mpatch.PatchMethod((*migrate.Migrate).Close, func(_ *migrate.Migrate) (error, error) {
			closeCalled = true
			return nil, nil
		})
		require.NoError(t, err, "Failed to patch Close method")
		defer safeUnpatch(t, closePatch)

		err = postgres.MigrateDSN(ctx, dsn, migrationsPath)
		assert.NoError(t, err)

		assert.True(t, upCalled, "Up method should have been called")
		assert.True(t, closeCalled, "Close method should have been called")
	})

	t.Run("error creating migration instance", func(t *testing.T) {
		expectedErr := errors.New("migration creation failed")

		patch, err := mpatch.PatchMethod(migrate.New, func(source string, database string) (*migrate.Migrate, error) {
			return nil, expectedErr
		})
		require.NoError(t, err, "Failed to patch migrate.New")
		defer safeUnpatch(t, patch)

		err = postgres.MigrateDSN(ctx, dsn, migrationsPath)

		assert.Error(t, err)
		assert.Contains(t, err.Error(), "failed to create migration instance")
		assert.ErrorIs(t, err, expectedErr)
	})

	t.Run("error applying migrations", func(t *testing.T) {
		expectedErr := errors.New("migration failed")

		newPatch, err := mpatch.PatchMethod(migrate.New, func(source, database string) (*migrate.Migrate, error) {
			return nil, nil
		})
		require.NoError(t, err, "Failed to patch migrate.New")
		defer safeUnpatch(t, newPatch)

		upPatch, err := mpatch.PatchMethod((*migrate.Migrate).Up, func(_ *migrate.Migrate) error {
			return expectedErr
		})
		require.NoError(t, err, "Failed to patch Up method")
		defer safeUnpatch(t, upPatch)

		closePatch, err := mpatch.PatchMethod((*migrate.Migrate).Close, func(_ *migrate.Migrate) (error, error) {
			return nil, nil
		})
		require.NoError(t, err, "Failed to patch Close method")
		defer safeUnpatch(t, closePatch)

		err = postgres.MigrateDSN(ctx, dsn, migrationsPath)

		assert.Error(t, err)
		assert.Contains(t, err.Error(), "failed to apply migrations")
		assert.ErrorIs(t, err, expectedErr)
	})

	t.Run("no changes needed case", func(t *testing.T) {
		newPatch, err := mpatch.PatchMethod(migrate.New, func(source, database string) (*migrate.Migrate, error) {
			return nil, nil
		})
		require.NoError(t, err, "Failed to patch migrate.New")
		defer safeUnpatch(t, newPatch)

		upPatch, err := mpatch.PatchMethod((*migrate.Migrate).Up, func(_ *migrate.Migrate) error {
			return migrate.ErrNoChange
		})
		require.NoError(t, err, "Failed to patch Up method")
		defer safeUnpatch(t, upPatch)

		closePatch, err := mpatch.PatchMethod((*migrate.Migrate).Close, func(_ *migrate.Migrate) (error, error) {
			return nil, nil
		})
		require.NoError(t, err, "Failed to patch Close method")
		defer safeUnpatch(t, closePatch)

		err = postgres.MigrateDSN(ctx, dsn, migrationsPath)

		assert.NoError(t, err)
	})
}
