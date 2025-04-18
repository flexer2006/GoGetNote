package postgres

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5/pgxpool"
	"go.uber.org/zap"

	"gogetnote/pkg/logger"
)

// Константы для сообщений logger.
const (
	LogConnecting        = "connecting to Postgres database"
	LogConnected         = "successfully connected to Postgres"
	LogClosing           = "closing Postgres connection pool"
	LogMigrationsApplied = "database migrations successfully applied"
)

// Константы для сообщений об ошибках.
const (
	ErrParseConfig  = "failed to parse connection config"
	ErrCreatePool   = "failed to create connection pool"
	ErrPingDatabase = "failed to ping database"
)

// Database представляет соединение с Postgres.
type Database struct {
	pool *pgxpool.Pool
}

// New создает новое соединение с базой данных Postgres.
func New(ctx context.Context, dsn string, minConn, maxConn int) (*Database, error) {
	log := logger.Log(ctx)

	log.Info(ctx, LogConnecting)

	poolCfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		log.Error(ctx, ErrParseConfig, zap.Error(err))
		return nil, fmt.Errorf("%s: %w", ErrParseConfig, err)
	}

	poolCfg.MinConns = int32(minConn)
	poolCfg.MaxConns = int32(maxConn)

	pool, err := pgxpool.NewWithConfig(ctx, poolCfg)
	if err != nil {
		log.Error(ctx, ErrCreatePool, zap.Error(err))
		return nil, fmt.Errorf("%s: %w", ErrCreatePool, err)
	}

	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		log.Error(ctx, ErrPingDatabase, zap.Error(err))
		return nil, fmt.Errorf("%s: %w", ErrPingDatabase, err)
	}

	log.Info(ctx, LogConnected)
	return &Database{pool: pool}, nil
}

// Pool возвращает подключение к пулу соединений.
func (db *Database) Pool() *pgxpool.Pool {
	return db.pool
}

// Close закрывает соединение с базой данных.
func (db *Database) Close(ctx context.Context) {
	logger.Log(ctx).Info(ctx, LogClosing)
	db.pool.Close()
}

// Ping проверяет доступность базы данных.
func (db *Database) Ping(ctx context.Context) error {
	return db.pool.Ping(ctx)
}
