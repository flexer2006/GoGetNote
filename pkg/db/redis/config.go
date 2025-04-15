// Package redis предоставляет общую реализацию клиента Redis.
package redis

import "time"

// DefaultValues содержит значения по умолчанию для Redis
// Значения должны быть синхронизированы с тегами env-default в RedisConfig Gateway
const (
	DefaultHost     = "redis"
	DefaultPort     = 6379
	DefaultPassword = ""
	DefaultDB       = 0
	DefaultPoolSize = 10
	DefaultTimeout  = 5 * time.Second
)

// Config содержит настройки подключения к Redis.
type Config struct {
	Host     string
	Port     int
	Password string
	DB       int
	PoolSize int
	Timeout  time.Duration
}

// DefaultConfig возвращает конфигурацию Redis по умолчанию.
func DefaultConfig() *Config {
	return &Config{
		Host:     DefaultHost,
		Port:     DefaultPort,
		Password: DefaultPassword,
		DB:       DefaultDB,
		PoolSize: DefaultPoolSize,
		Timeout:  DefaultTimeout,
	}
}

// NewConfigFromGatewayConfig создает конфигурацию Redis из конфигурации Gateway.
func NewConfigFromGatewayConfig(cfg RedisGatewayConfig) *Config {
	return &Config{
		Host:     cfg.GetHost(),
		Port:     cfg.GetPort(),
		Password: cfg.GetPassword(),
		DB:       cfg.GetDB(),
		PoolSize: cfg.GetPoolSize(),
		Timeout:  DefaultTimeout, // Используем значение по умолчанию, т.к. его нет в Gateway
	}
}

// RedisGatewayConfig представляет конфигурацию Redis из Gateway
type RedisGatewayConfig interface {
	GetHost() string
	GetPort() int
	GetPassword() string
	GetDB() int
	GetPoolSize() int
}
