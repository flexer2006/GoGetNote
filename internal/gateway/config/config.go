// Package config содержит конфигурацию для Gateway сервиса.
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
	LogLoadingConfig    = "Loading gateway service configuration"
	LogConfigLoaded     = "Configuration loaded successfully"
	ErrFailedLoadConfig = "Failed to load configuration"
)

// Config представляет полную конфигурацию Gateway.
type Config struct {
	HTTP     HTTPConfig       `yaml:"http"`
	GRPC     GRPCClientConfig `yaml:"grpc"`
	Logging  LoggingConfig    `yaml:"logging"`
	Shutdown ShutdownConfig   `yaml:"shutdown"`
	Redis    RedisConfig      `yaml:"redis"`
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
		zap.String("http_host", cfg.HTTP.Host),
		zap.Int("http_port", cfg.HTTP.Port),
		zap.String("log_level", cfg.Logging.Level),
		zap.String("log_mode", cfg.Logging.Mode),
		zap.Int("shutdown_timeout_seconds", cfg.Shutdown.Timeout),
		zap.String("auth_service_address", cfg.GRPC.AuthService.GetAddress()),
		zap.String("redis_address", cfg.Redis.GetAddressString()),
		zap.Duration("redis_default_ttl", cfg.Redis.DefaultTTL))

	return &cfg, nil
}

// GetEnvironment возвращает режим работы логгера.
func (c *LoggingConfig) GetEnvironment() logger.Environment {
	if c.Mode == "development" {
		return logger.Development
	}
	return logger.Production
}
