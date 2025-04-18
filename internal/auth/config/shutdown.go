package config

import (
	"time"
)

// ShutdownConfig содержит настройки для graceful shutdown.
type ShutdownConfig struct {
	Timeout int `yaml:"timeout" env:"AUTH_GRACEFUL_SHUTDOWN_TIMEOUT" env-default:"5"`
}

// GetTimeout возвращает timeout как time.Duration.
func (s *ShutdownConfig) GetTimeout() time.Duration {
	return time.Duration(s.Timeout) * time.Second
}
