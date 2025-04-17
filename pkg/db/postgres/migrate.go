package postgres

import (
	"context"
	"errors"
	"fmt"

	"github.com/golang-migrate/migrate/v4"
	_ "github.com/golang-migrate/migrate/v4/database/postgres"
	_ "github.com/golang-migrate/migrate/v4/source/file"
	"go.uber.org/zap"

	"gogetnote/pkg/logger"
)

// Константы для сообщений об ошибках миграций.
const (
	ErrCreateMigrationInstance = "failed to create migration instance"
	ErrApplyMigrations         = "failed to apply migrations"
)

// MigrateDSN выполняет миграции базы данных из указанного пути.
func MigrateDSN(ctx context.Context, dsn string, migrationsPath string) error {
	log := logger.Log(ctx)

	m, err := migrate.New(migrationsPath, dsn)
	if err != nil {
		log.Error(ctx, ErrCreateMigrationInstance, zap.Error(err), zap.String("path", migrationsPath))
		return fmt.Errorf("%s: %w", ErrCreateMigrationInstance, err)
	}
	defer m.Close()

	if err := m.Up(); err != nil && !errors.Is(err, migrate.ErrNoChange) {
		log.Error(ctx, ErrApplyMigrations, zap.Error(err))
		return fmt.Errorf("%s: %w", ErrApplyMigrations, err)
	}

	log.Info(ctx, LogMigrationsApplied)
	return nil
}
