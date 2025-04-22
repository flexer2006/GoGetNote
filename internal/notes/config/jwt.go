package config

import "time"

// JWTConfig содержит настройки для JWT токенов.
type JWTConfig struct {
	SecretKey       string `yaml:"secret_key" env:"JWT_SECRET_KEY" env-default:"2hlsdwbzmv7yGxbQ4sIah/MuvvNoe889pbEzZql0SU8n3U1gYi29gZnFQKxiUdGH"`
	AccessTokenTTL  string `yaml:"access_token_ttl" env:"JWT_ACCESS_TOKEN_TTL" env-default:"15m"`
	RefreshTokenTTL string `yaml:"refresh_token_ttl" env:"JWT_REFRESH_TOKEN_TTL" env-default:"24h"`
	BCryptCost      int    `yaml:"bcrypt_cost" env:"JWT_BCRYPT_COST" env-default:"10"`
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
