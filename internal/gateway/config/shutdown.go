package config

import "time"

// ShutdownConfig представляет конфигурацию для корректного завершения работы.
type ShutdownConfig struct {
	Timeout int `yaml:"timeout" env:"GATEWAY_GRACEFUL_SHUTDOWN_TIMEOUT" env-default:"5"`
}

// GetTimeout возвращает таймаут для корректного завершения работы в виде Duration.
func (c *ShutdownConfig) GetTimeout() time.Duration {
	return time.Duration(c.Timeout) * time.Second
}
