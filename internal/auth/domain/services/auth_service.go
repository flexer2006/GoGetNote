package services

import (
	"errors"
	"time"
)

// Ошибки домена аутентификации.
var (
	ErrInvalidCredentials    = errors.New("invalid email or password")
	ErrEmailAlreadyExists    = errors.New("user with this email already exists")
	ErrInvalidRefreshToken   = errors.New("invalid refresh token")
	ErrRevokedRefreshToken   = errors.New("refresh token has been revoked")
	ErrTokenGenerationFailed = errors.New("failed to generate authentication tokens")
)

// TokenPair представляет пару токенов аутентификации.
type TokenPair struct {
	UserID       string
	Username     string
	AccessToken  string
	RefreshToken string
	ExpiresAt    time.Time
}

// RefreshToken представляет сущность refresh-токена.
type RefreshToken struct {
	ID        string
	UserID    string
	Token     string
	ExpiresAt time.Time
	CreatedAt time.Time
	IsRevoked bool
}
