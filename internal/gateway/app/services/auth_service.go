// Package services содержит реализации сервисов для Gateway.
// Включает сервисы авторизации и управления пользователями.
package services

import (
	"context"
	"fmt"

	"go.uber.org/zap"

	"gogetnote/internal/gateway/app/dto"
	"gogetnote/internal/gateway/ports/cache"
	"gogetnote/internal/gateway/ports/grpc"
	"gogetnote/internal/gateway/ports/services"
	"gogetnote/internal/gateway/resilience"
	"gogetnote/pkg/logger"
	"time"
)

// Константы для логирования.
const (
	LogServiceRegister     = "auth service: register user"
	LogServiceLogin        = "auth service: login user"
	LogServiceTokenRefresh = "auth service: token refresh" // nolint:gosec
	LogServiceLogout       = "auth service: logout"
	LogServiceGetProfile   = "auth service: get user profile"

	ErrorRegisterFailed     = "failed to register user"
	ErrorLoginFailed        = "failed to login"
	ErrorUpdateTokensFailed = "failed to update tokens"
	ErrorLogoutFailed       = "failed to logout"
	ErrorGetProfileFailed   = "failed to get user profile"
)

// Константы для кэширования.
const (
	ProfileCacheKeyPrefix = "profile:"
	TokenCacheKeyPrefix   = "token:"
)

// AuthServiceImpl реализует интерфейс AuthService.
type AuthServiceImpl struct {
	authClient grpc.AuthServiceClient
	cache      cache.Cache
	resilience *resilience.ServiceResilience
}

// NewAuthService создает новый экземпляр сервиса авторизации.
func NewAuthService(authClient grpc.AuthServiceClient, cache cache.Cache) services.AuthService {
	return &AuthServiceImpl{
		authClient: authClient,
		cache:      cache,
		resilience: resilience.NewServiceResilience("auth-service"),
	}
}

// Register регистрирует нового пользователя.
func (s *AuthServiceImpl) Register(ctx context.Context, req *dto.RegisterRequest) (*dto.TokenResponse, error) {
	log := logger.Log(ctx)
	log.Info(ctx, LogServiceRegister)

	result, err := s.resilience.ExecuteWithResultTokenResponse(ctx, "Register", func() (interface{}, error) {
		response, err := s.authClient.Register(ctx, req.Email, req.Username, req.Password)
		if err != nil {
			log.Error(ctx, ErrorRegisterFailed, zap.Error(err))
			return nil, fmt.Errorf("%s: %w", ErrorRegisterFailed, err)
		}

		return &dto.TokenResponse{
			UserID:       response.UserId,
			AccessToken:  response.AccessToken,
			RefreshToken: response.RefreshToken,
			ExpiresAt:    response.ExpiresAt.AsTime(),
		}, nil
	})

	if err != nil {
		return nil, fmt.Errorf("user registration failed: %w", err)
	}

	return result.(*dto.TokenResponse), nil
}

// Login выполняет вход пользователя в систему.
func (s *AuthServiceImpl) Login(ctx context.Context, req *dto.LoginRequest) (*dto.TokenResponse, error) {
	log := logger.Log(ctx)
	log.Info(ctx, LogServiceLogin)

	result, err := s.resilience.ExecuteWithResultTokenResponse(ctx, "Login", func() (interface{}, error) {
		response, err := s.authClient.Login(ctx, req.Email, req.Password)
		if err != nil {
			log.Error(ctx, ErrorLoginFailed, zap.Error(err))
			return nil, fmt.Errorf("%s: %w", ErrorLoginFailed, err)
		}

		return &dto.TokenResponse{
			UserID:       response.UserId,
			Username:     response.Username,
			AccessToken:  response.AccessToken,
			RefreshToken: response.RefreshToken,
			ExpiresAt:    response.ExpiresAt.AsTime(),
		}, nil
	})

	if err != nil {
		return nil, fmt.Errorf("user login failed: %w", err)
	}

	return result.(*dto.TokenResponse), nil
}

// RefreshTokens обновляет токены доступа.
func (s *AuthServiceImpl) RefreshTokens(ctx context.Context, req *dto.RefreshRequest) (*dto.TokenResponse, error) {
	log := logger.Log(ctx)
	log.Info(ctx, LogServiceTokenRefresh)

	result, err := s.resilience.ExecuteWithResultTokenResponse(ctx, "RefreshTokens", func() (interface{}, error) {
		response, err := s.authClient.RefreshTokens(ctx, req.RefreshToken)
		if err != nil {
			log.Error(ctx, ErrorUpdateTokensFailed, zap.Error(err))
			return nil, fmt.Errorf("%s: %w", ErrorUpdateTokensFailed, err)
		}

		return &dto.TokenResponse{
			AccessToken:  response.AccessToken,
			RefreshToken: response.RefreshToken,
			ExpiresAt:    response.ExpiresAt.AsTime(),
		}, nil
	})

	if err != nil {
		return nil, fmt.Errorf("token refresh failed: %w", err)
	}

	return result.(*dto.TokenResponse), nil
}

// Logout выполняет выход пользователя из системы.
func (s *AuthServiceImpl) Logout(ctx context.Context, req *dto.LogoutRequest) error {
	log := logger.Log(ctx)
	log.Info(ctx, LogServiceLogout)

	err := s.resilience.ExecuteWithResilience(ctx, "Logout", func() error {
		err := s.authClient.Logout(ctx, req.RefreshToken)
		if err != nil {
			log.Error(ctx, ErrorLogoutFailed, zap.Error(err))
			return fmt.Errorf("%s: %w", ErrorLogoutFailed, err)
		}

		if req.RefreshToken != "" {
			tokenHash := hashToken(req.RefreshToken)
			cacheKey := ProfileCacheKeyPrefix + tokenHash

			cacheCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
			defer cancel()

			if err := s.cache.Delete(cacheCtx, cacheKey); err != nil {
				log.Warn(ctx, "Failed to invalidate profile cache", zap.Error(err))
			}
		}

		return nil
	})

	if err != nil {
		return fmt.Errorf("user logout failed: %w", err)
	}

	return nil
}
