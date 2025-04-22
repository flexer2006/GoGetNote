package config

// LoggingConfig представляет конфигурацию логирования.
type LoggingConfig struct {
	Level string `yaml:"level" env:"GATEWAY_LOGGER_LEVEL" env-default:"info"`
	Mode  string `yaml:"mode" env:"GATEWAY_LOGGER_MODE" env-default:"production"`
}
