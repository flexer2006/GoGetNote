package config

import (
	"fmt"
	"strconv"
	"time"
)

// RedisConfig представляет конфигурацию для Redis.
type RedisConfig struct {
	Host            string        `yaml:"host" env:"GATEWAY_REDIS_HOST" env-default:"localhost"`
	Port            int           `yaml:"port" env:"GATEWAY_REDIS_PORT" env-default:"6379"`
	Password        string        `yaml:"password" env:"GATEWAY_REDIS_PASSWORD" env-default:""`
	DB              int           `yaml:"db" env:"GATEWAY_REDIS_DB" env-default:"0"`
	ConnectTimeout  time.Duration `yaml:"connect_timeout" env:"GATEWAY_REDIS_CONNECT_TIMEOUT" env-default:"5s"`
	ReadTimeout     time.Duration `yaml:"read_timeout" env:"GATEWAY_REDIS_READ_TIMEOUT" env-default:"3s"`
	WriteTimeout    time.Duration `yaml:"write_timeout" env:"GATEWAY_REDIS_WRITE_TIMEOUT" env-default:"3s"`
	PoolSize        int           `yaml:"pool_size" env:"GATEWAY_REDIS_POOL_SIZE" env-default:"10"`
	MinIdle         int           `yaml:"min_idle" env:"GATEWAY_REDIS_MIN_IDLE" env-default:"2"`
	IdleTimeout     time.Duration `yaml:"idle_timeout" env:"GATEWAY_REDIS_IDLE_TIMEOUT" env-default:"5m"`
	MaxConnLifetime time.Duration `yaml:"max_conn_lifetime" env:"GATEWAY_REDIS_MAX_CONN_LIFETIME" env-default:"1h"`
	DefaultTTL      time.Duration `yaml:"default_ttl" env:"GATEWAY_REDIS_DEFAULT_TTL" env-default:"15m"`
}

// GetAddress возвращает адрес Redis.
func (c *RedisConfig) GetAddress() string {
	return fmt.Sprintf("%s:%d", c.Host, c.Port)
}

// GetAddressString возвращает адрес Redis строкой.
func (c *RedisConfig) GetAddressString() string {
	return c.Host + ":" + strconv.Itoa(c.Port)
}
