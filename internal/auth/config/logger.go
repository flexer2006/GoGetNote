package config

import (
	"gogetnote/pkg/logger"
)

// LoggingConfig содержит настройки логирования.
type LoggingConfig struct {
	Level string `yaml:"level" env:"AUTH_LOGGER_LEVEL" env-default:"info"`
	Mode  string `yaml:"mode" env:"AUTH_LOGGER_MODE" env-default:"development"`
}

// GetEnvironment получает строку режима в logger.Environment.
func (l *LoggingConfig) GetEnvironment() logger.Environment {
	if l.Mode == "production" {
		return logger.Production
	}
	return logger.Development
}
