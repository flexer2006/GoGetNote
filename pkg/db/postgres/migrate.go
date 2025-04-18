package postgres

import (
	"context"
	"errors"
	"fmt"

	"github.com/golang-migrate/migrate/v4"
	// Импортируем драйвер для работы с Postgres.
	_ "github.com/golang-migrate/migrate/v4/database/postgres"
	// Импортируем драйвер для чтения миграций из файлов.
	_ "github.com/golang-migrate/migrate/v4/source/file"
	"go.uber.org/zap"

	"gogetnote/pkg/logger"
)

// Константы для сообщений об ошибках миграций.
const (
	ErrCreateMigrationInstance      = "failed to create migration instance"
	ErrApplyMigrations              = "failed to apply migrations"
	ErrFailedCloseMigrationInstance = "failed to close migration instance"
)

// MigrateDSN выполняет миграции базы данных из указанного пути.
func MigrateDSN(ctx context.Context, dsn string, migrationsPath string) error {
	log := logger.Log(ctx)

	migrator, err := migrate.New(migrationsPath, dsn)
	if err != nil {
		log.Error(ctx, ErrCreateMigrationInstance, zap.Error(err), zap.String("path", migrationsPath))
		return fmt.Errorf("%s: %w", ErrCreateMigrationInstance, err)
	}
	defer func() {
		_, closeErr := migrator.Close()
		if closeErr != nil {
			log.Error(ctx, ErrFailedCloseMigrationInstance, zap.Error(closeErr))
		}
	}()

	if err := migrator.Up(); err != nil && !errors.Is(err, migrate.ErrNoChange) {
		log.Error(ctx, ErrApplyMigrations, zap.Error(err))
		return fmt.Errorf("%s: %w", ErrApplyMigrations, err)
	}

	log.Info(ctx, LogMigrationsApplied)
	return nil
}
