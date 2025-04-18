package api

import (
	"context"

	"gogetnote/internal/auth/domain/services"
)

// AuthUseCase определяет основной порт для операций аутентификации.
type AuthUseCase interface {
	Register(ctx context.Context, email, username, password string) (*services.TokenPair, error)

	Login(ctx context.Context, email, password string) (*services.TokenPair, error)

	RefreshTokens(ctx context.Context, refreshToken string) (*services.TokenPair, error)

	Logout(ctx context.Context, refreshToken string) error
}
