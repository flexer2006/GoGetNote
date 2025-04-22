package config

import (
	"fmt"
	"time"
)

// GRPCClientConfig представляет конфигурацию для gRPC клиентов Gateway.
type GRPCClientConfig struct {
	AuthService    GRPCServiceConfig `yaml:"auth_service" env-prefix:"GATEWAY_GRPC_AUTH_"`
	NotesService   GRPCServiceConfig `yaml:"notes_service" env-prefix:"GATEWAY_GRPC_NOTES_"`
	RequestTimeout time.Duration     `yaml:"request_timeout" env:"GATEWAY_GRPC_REQUEST_TIMEOUT" env-default:"5s"`
}

// GRPCServiceConfig представляет конфигурацию для подключения к gRPC сервису.
type GRPCServiceConfig struct {
	Host           string        `yaml:"host" env:"HOST" env-default:"localhost"`
	Port           int           `yaml:"port" env:"PORT" env-default:"50051"`
	ConnectTimeout time.Duration `yaml:"connect_timeout" env:"GATEWAY_TO_AUTHCONNECT_TIMEOUT" env-default:"5s"`
}

// GetAddress возвращает адрес gRPC сервиса в формате host:port.
func (c *GRPCServiceConfig) GetAddress() string {
	return fmt.Sprintf("%s:%d", c.Host, c.Port)
}
