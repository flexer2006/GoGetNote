package repositories

import (
	"context"

	"gogetnote/internal/auth/domain/services"
)

// TokenRepository определяет интерфейс для операций по управлению токенами.
type TokenRepository interface {
	StoreRefreshToken(ctx context.Context, token *services.RefreshToken) error

	FindByToken(ctx context.Context, token string) (*services.RefreshToken, error)

	RevokeToken(ctx context.Context, token string) error

	RevokeAllUserTokens(ctx context.Context, userID string) error

	CleanupExpiredTokens(ctx context.Context) error

	FindUserTokens(ctx context.Context, userID string) ([]*services.RefreshToken, error)
}
