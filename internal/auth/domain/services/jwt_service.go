package services

import (
	"errors"
	"time"
)

// JWTErrors содержит ошибки, связанные с JWT токенами.
var (
	ErrInvalidJWTToken    = errors.New("invalid JWT token")
	ErrExpiredJWTToken    = errors.New("JWT token has expired")
	ErrGeneratingJWTToken = errors.New("failed to generate JWT token")
)

// JWTConfig содержит настройки для JWT сервиса.
type JWTConfig struct {
	SecretKey       []byte
	AccessTokenTTL  time.Duration
	RefreshTokenTTL time.Duration
}

// JWTClaims определяет структуру данных JWT токена.
type JWTClaims struct {
	UserID    string    `json:"user_id"`
	Username  string    `json:"username,omitempty"`
	IssuedAt  time.Time `json:"iat"`
	ExpiresAt time.Time `json:"exp"`
}
