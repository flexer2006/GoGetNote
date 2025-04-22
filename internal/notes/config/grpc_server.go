package config

import (
	"fmt"
)

// GRPCConfig конфигурация gRPC сервера.
type GRPCConfig struct {
	Host string `yaml:"host" env:"NOTES_GRPC_HOST" env-default:"0.0.0.0"`
	Port int    `yaml:"port" env:"NOTES_GRPC_PORT" env-default:"50053"`
}

// GetAddress возвращает адрес для gRPC сервера.
func (g *GRPCConfig) GetAddress() string {
	return fmt.Sprintf("%s:%d", g.Host, g.Port)
}
