package config

import (
	"fmt"
	"time"
)

// HTTPConfig представляет конфигурацию HTTP сервера.
type HTTPConfig struct {
	Host            string        `yaml:"host" env:"GATEWAY_HTTP_HOST" env-default:"0.0.0.0"`
	Port            int           `yaml:"port" env:"GATEWAY_HTTP_PORT" env-default:"8080"`
	ReadTimeout     time.Duration `yaml:"read_timeout" env:"GATEWAY_HTTP_READ_TIMEOUT" env-default:"5s"`
	WriteTimeout    time.Duration `yaml:"write_timeout" env:"GATEWAY_HTTP_WRITE_TIMEOUT" env-default:"10s"`
	ShutdownTimeout time.Duration `yaml:"shutdown_timeout" env:"GATEWAY_HTTP_SHUTDOWN_TIMEOUT" env-default:"5s"`
}

// GetAddress возвращает адрес HTTP сервера.
func (c *HTTPConfig) GetAddress() string {
	return fmt.Sprintf("%s:%d", c.Host, c.Port)
}
