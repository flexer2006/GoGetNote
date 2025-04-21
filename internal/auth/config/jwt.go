package config

import "time"

// JWTConfig содержит настройки для JWT токенов.
type JWTConfig struct {
	SecretKey       string `yaml:"secret_key" env:"AUTH_JWT_SECRET_KEY" env-default:"super-secret-key-change-me-in-production"`
	AccessTokenTTL  string `yaml:"access_token_ttl" env:"AUTH_JWT_ACCESS_TOKEN_TTL" env-default:"15m"`
	RefreshTokenTTL string `yaml:"refresh_token_ttl" env:"AUTH_JWT_REFRESH_TOKEN_TTL" env-default:"24h"`
	BCryptCost      int    `yaml:"bcrypt_cost" env:"AUTH_JWT_BCRYPT_COST" env-default:"10"`
}

// GetAccessTokenTTL возвращает продолжительность времени жизни access токена.
func (c *JWTConfig) GetAccessTokenTTL() time.Duration {
	duration, err := time.ParseDuration(c.AccessTokenTTL)
	if err != nil {
		return 15 * time.Minute
	}
	return duration
}

// GetRefreshTokenTTL возвращает продолжительность времени жизни refresh токена.
func (c *JWTConfig) GetRefreshTokenTTL() time.Duration {
	duration, err := time.ParseDuration(c.RefreshTokenTTL)
	if err != nil {
		return 24 * time.Hour
	}
	return duration
}
