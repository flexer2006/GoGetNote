// Package db предоставляет функционал для работы с базой данных сервиса аутентификации.
package db

import (
	"context"
	"fmt"
	"path/filepath"

	"github.com/jackc/pgx/v5/pgxpool"
	"go.uber.org/zap"

	"gogetnote/internal/notes/config"
	"gogetnote/pkg/db/postgres"
	"gogetnote/pkg/logger"
)

// Константы для сообщений logger.
const (
	LogDBInitializing    = "initializing authentication database"
	LogDBInitialized     = "authentication database initialized successfully"
	LogMigrationStarting = "starting database migrations for authentication service"
)

// Константы для сообщений об ошибках.
const (
	ErrDBMigrations      = "failed to apply authentication database migrations"
	ErrDBConnection      = "failed to connect to authentication database"
	ErrGetPath           = "failed to get path"
	ErrDBCheckConnection = "error checking the database connection"
)
const filePrefix = "file://"

// DB представляет соединение с базой данных сервиса авторизации.
type DB struct {
	database *postgres.Database
}

// New инициализирует соединение с базой данных, предварительно применив миграции.
func New(ctx context.Context, cfg *config.PostgresConfig, migrationsDir string) (*DB, error) {
	log := logger.Log(ctx)

	log.Info(ctx, LogDBInitializing,
		zap.String("host", cfg.Host),
		zap.Int("port", cfg.Port),
		zap.String("database", cfg.Database),
		zap.Int("min_conn", cfg.MinConn),
		zap.Int("max_conn", cfg.MaxConn))

	var migrationsPath string
	if !filepath.IsAbs(migrationsDir) {
		absPath, err := filepath.Abs(migrationsDir)
		if err != nil {
			return nil, fmt.Errorf("%s: %s: %w", ErrDBMigrations, ErrGetPath, err)
		}
		migrationsPath = filePrefix + absPath
	} else {
		migrationsPath = filePrefix + migrationsDir
	}

	log.Info(ctx, LogMigrationStarting, zap.String("migrations_path", migrationsPath))
	if err := postgres.MigrateDSN(ctx, cfg.GetConnectionURL(), migrationsPath); err != nil {
		return nil, fmt.Errorf("%s: %w", ErrDBMigrations, err)
	}

	database, err := postgres.New(ctx, cfg.GetDSN(), cfg.MinConn, cfg.MaxConn)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", ErrDBConnection, err)
	}

	log.Info(ctx, LogDBInitialized)

	return &DB{
		database: database,
	}, nil
}

// Close закрывает соединение с базой данных.
func (db *DB) Close(ctx context.Context) {
	db.database.Close(ctx)
}

// Pool возвращает пул соединений с базой данных.
func (db *DB) Pool() *pgxpool.Pool {
	return db.database.Pool()
}

// Ping проверяет соединение с базой данных.
func (db *DB) Ping(ctx context.Context) error {
	if err := db.database.Ping(ctx); err != nil {
		return fmt.Errorf("%s: %w", ErrDBCheckConnection, err)
	}
	return nil
}

// Database возвращает доступ к базовой реализации для расширенных операций.
func (db *DB) Database() *postgres.Database {
	return db.database
}
