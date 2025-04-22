package config

import (
	"fmt"
)

// PostgresConfig содержит настройки подключения к базе данных.
type PostgresConfig struct {
	Host     string `yaml:"host" env:"NOTES_POSTGRES_HOST" env-default:"0.0.0.0"`
	Port     int    `yaml:"port" env:"NOTES_POSTGRES_PORT" env-default:"5433"`
	User     string `yaml:"user" env:"NOTES_POSTGRES_USER" env-default:"postgres"`
	Password string `yaml:"password" env:"NOTES_POSTGRES_PASSWORD" env-default:"postgres"`
	Database string `yaml:"database" env:"NOTES_POSTGRES_DB" env-default:"notes"`
	MinConn  int    `yaml:"min_conn" env:"NOTES_POSTGRES_MIN_CONN" env-default:"1"`
	MaxConn  int    `yaml:"max_conn" env:"NOTES_POSTGRES_MAX_CONN" env-default:"10"`
}

// GetDSN возвращает строку подключения к Postgres.
func (p *PostgresConfig) GetDSN() string {
	return fmt.Sprintf("host=%s port=%d user=%s password=%s dbname=%s sslmode=disable",
		p.Host, p.Port, p.User, p.Password, p.Database)
}

// GetConnectionURL возвращает URL-строку подключения для миграций.
func (p *PostgresConfig) GetConnectionURL() string {
	return fmt.Sprintf("postgres://%s:%s@%s:%d/%s?sslmode=disable",
		p.User, p.Password, p.Host, p.Port, p.Database)
}
