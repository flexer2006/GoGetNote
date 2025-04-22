// Package grpc определяет интерфейсы для взаимодействия с gRPC сервисами.
package grpc

import (
	"context"

	authv1 "gogetnote/pkg/api/auth/v1"
)

// AuthServiceClient определяет интерфейс для взаимодействия с сервисом авторизации.
type AuthServiceClient interface {
	Register(ctx context.Context, email, username, password string) (*authv1.RegisterResponse, error)

	Login(ctx context.Context, email, password string) (*authv1.LoginResponse, error)

	RefreshTokens(ctx context.Context, refreshToken string) (*authv1.RefreshTokensResponse, error)

	Logout(ctx context.Context, refreshToken string) error

	GetUserProfile(ctx context.Context) (*authv1.UserProfileResponse, error)
}
