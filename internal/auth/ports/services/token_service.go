package services

import (
	"context"
	"time"
)

// TokenService определяет интерфейс для операций с токенами JWT.
type TokenService interface {
	GenerateAccessToken(ctx context.Context, userID, username string) (string, time.Time, error)

	GenerateRefreshToken(ctx context.Context, userID string) (string, time.Time, error)

	ValidateAccessToken(ctx context.Context, token string) (string, error)
}
