// Package services defines service interfaces for the notes service.
package services

import (
	"context"
	"errors"
)

// TokenService определяет интерфейс для работы с JWT токенами.
type TokenService interface {
	ValidateAccessToken(ctx context.Context, token string) (string, error)
}

// JWTErrors содержит ошибки, связанные с JWT токенами.
var (
	ErrInvalidJWTToken = errors.New("invalid JWT token")
	ErrExpiredJWTToken = errors.New("JWT token has expired")
)
