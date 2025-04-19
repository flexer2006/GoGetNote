// Package config содержит конфигурацию для аутентификационного сервиса.
package config

import (
	"context"
	"fmt"

	"gogetnote/pkg/logger"

	"github.com/ilyakaznacheev/cleanenv"
	"go.uber.org/zap"
)

// Константы ошибок и сообщений для конфигурации.
const (
	LogLoadingConfig    = "Loading authentication service configuration"
	LogConfigLoaded     = "Configuration loaded successfully"
	ErrFailedLoadConfig = "Failed to load configuration"
)

// Config представляет полную конфигурацию приложения.
type Config struct {
	Postgres PostgresConfig `yaml:"postgres"`
	Logging  LoggingConfig  `yaml:"logging"`
	Shutdown ShutdownConfig `yaml:"shutdown"`
}

// Load загружает конфигурацию из переменных окружения.
func Load(ctx context.Context) (*Config, error) {
	log := logger.Log(ctx)

	log.Info(ctx, LogLoadingConfig)

	var cfg Config
	err := cleanenv.ReadEnv(&cfg)
	if err != nil {
		log.Error(ctx, ErrFailedLoadConfig, zap.Error(err))
		return nil, fmt.Errorf("%s: %w", ErrFailedLoadConfig, err)
	}

	log.Info(ctx, LogConfigLoaded,
		zap.String("postgres_host", cfg.Postgres.Host),
		zap.Int("postgres_port", cfg.Postgres.Port),
		zap.String("log_level", cfg.Logging.Level),
		zap.String("log_mode", cfg.Logging.Mode),
		zap.Int("shutdown_timeout_seconds", cfg.Shutdown.Timeout),
		zap.Int("postgres_min_conn", cfg.Postgres.MinConn),
		zap.Int("postgres_max_conn", cfg.Postgres.MaxConn))

	return &cfg, nil
}
