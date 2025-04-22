// Package services определяет интерфейсы сервисов Gateway.
package services

import (
	"context"

	"gogetnote/internal/gateway/app/dto"
)

// AuthService определяет интерфейс для работы с сервисом авторизации.
type AuthService interface {
	Register(ctx context.Context, req *dto.RegisterRequest) (*dto.TokenResponse, error)

	Login(ctx context.Context, req *dto.LoginRequest) (*dto.TokenResponse, error)

	RefreshTokens(ctx context.Context, req *dto.RefreshRequest) (*dto.TokenResponse, error)

	Logout(ctx context.Context, req *dto.LogoutRequest) error

	GetUserProfile(ctx context.Context) (*dto.UserProfileResponse, error)
}
