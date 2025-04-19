// Package grpc предоставляет реализацию gRPC сервера для аутентификационного сервиса.
package grpc

import (
	"context"
	"fmt"
	"google.golang.org/grpc"

	"go.uber.org/zap"
	"google.golang.org/protobuf/types/known/emptypb"
	"google.golang.org/protobuf/types/known/timestamppb"

	"gogetnote/internal/auth/ports/api"
	"gogetnote/pkg/api/auth/v1"
	"gogetnote/pkg/logger"
)

// Константы для логирования и кодов ошибок.
//
//nolint:gosec
const (
	LogRegisterRequest     = "processing register request"
	LogLoginRequest        = "processing login request"
	LogRefreshTokenRequest = "processing refresh token request"
	LogLogoutRequest       = "processing logout request"

	ErrInvalidCredentialsMsg  = "invalid credentials" // #nosec G101
	ErrInvalidTokenMsg        = "invalid refresh token"
	ErrAuthServiceInternalMsg = "internal authentication service error"
	ErrInvalidRequestMsg      = "invalid request data"
	ErrUserAlreadyExistsMsg   = "user already exists"

	ErrLogoutFailedTokenMsg      = "logout failed with invalid token"
	ErrLogoutOperationFailedMsg  = "logout operation failed"
	ErrRefreshTokensMsg          = "refreshTokens error"
	ErrMissingRefreshTokenMsg    = "missing refresh token"
	ErrMissingRefreshLogoutMsg   = "missing refresh token for logout"
	ErrRegisterMsg               = "register error"
	ErrUserRegistrationFailedMsg = "user registration failed"
	ErrAuthServiceErrorMsg       = "auth service error"
	ErrLoginMsg                  = "login error"
	ErrAuthenticationFailedMsg   = "authentication failed"
	ErrTokenRefreshFailedMsg     = "token refresh failed"
	ErrLogoutMsg                 = "logout error"
	ErrInvalidLoginParamsMsg     = "invalid login parameters"
	ErrInvalidRequestParamsMsg   = "invalid request parameters"
)

// Ошибки обработчика.
var (
	ErrInvalidRequest      = fmt.Errorf("%s", ErrInvalidRequestMsg)
	ErrInvalidCredentials  = fmt.Errorf("%s", ErrInvalidCredentialsMsg)
	ErrInvalidToken        = fmt.Errorf("%s", ErrInvalidTokenMsg)
	ErrAuthServiceInternal = fmt.Errorf("%s", ErrAuthServiceInternalMsg)
	ErrUserAlreadyExists   = fmt.Errorf("%s", ErrUserAlreadyExistsMsg)
)

// AuthHandler реализует gRPC интерфейс AuthService.
type AuthHandler struct {
	authUseCase api.AuthUseCase
	authv1.UnimplementedAuthServiceServer
}

// NewAuthHandler создает новый обработчик AuthService.
func NewAuthHandler(authUseCase api.AuthUseCase) *AuthHandler {
	return &AuthHandler{authUseCase: authUseCase}
}

// Register регистрирует нового пользователя.
func (h *AuthHandler) Register(ctx context.Context, req *authv1.RegisterRequest) (*authv1.RegisterResponse, error) {
	log := logger.Log(ctx)
	log.Info(ctx, LogRegisterRequest,
		zap.String("email", req.Email),
		zap.String("username", req.Username))

	if req.Email == "" || req.Username == "" || req.Password == "" {
		return nil, fmt.Errorf("%s: %w", ErrInvalidRequestParamsMsg, ErrInvalidRequest)
	}

	tokenPair, err := h.authUseCase.Register(ctx, req.Email, req.Username, req.Password)
	if err != nil {
		log.Error(ctx, fmt.Sprintf("%s: %v", ErrRegisterMsg, err))

		switch err.Error() {
		case ErrUserAlreadyExistsMsg:
			return nil, fmt.Errorf("%s: %w", ErrUserRegistrationFailedMsg, ErrUserAlreadyExists)
		default:
			return nil, fmt.Errorf("%s: %w", ErrAuthServiceErrorMsg, ErrAuthServiceInternal)
		}
	}

	return &authv1.RegisterResponse{
		UserId:       tokenPair.UserID,
		AccessToken:  tokenPair.AccessToken,
		RefreshToken: tokenPair.RefreshToken,
		ExpiresAt:    timestamppb.New(tokenPair.ExpiresAt),
	}, nil
}

// Login авторизует пользователя.
func (h *AuthHandler) Login(ctx context.Context, req *authv1.LoginRequest) (*authv1.LoginResponse, error) {
	log := logger.Log(ctx)
	log.Info(ctx, LogLoginRequest, zap.String("email", req.Email))

	if req.Email == "" || req.Password == "" {
		return nil, fmt.Errorf("%s: %w", ErrInvalidLoginParamsMsg, ErrInvalidRequest)
	}

	tokenPair, err := h.authUseCase.Login(ctx, req.Email, req.Password)
	if err != nil {
		log.Error(ctx, fmt.Sprintf("%s: %v", ErrLoginMsg, err))

		return nil, fmt.Errorf("%s: %w", ErrAuthenticationFailedMsg, ErrInvalidCredentials)
	}

	return &authv1.LoginResponse{
		UserId:       tokenPair.UserID,
		Username:     tokenPair.Username,
		AccessToken:  tokenPair.AccessToken,
		RefreshToken: tokenPair.RefreshToken,
		ExpiresAt:    timestamppb.New(tokenPair.ExpiresAt),
	}, nil
}

// RefreshTokens обновляет пару токенов.
func (h *AuthHandler) RefreshTokens(ctx context.Context, req *authv1.RefreshTokensRequest) (*authv1.RefreshTokensResponse, error) {
	log := logger.Log(ctx)
	log.Info(ctx, LogRefreshTokenRequest)

	if req.RefreshToken == "" {
		return nil, fmt.Errorf("%s: %w", ErrMissingRefreshTokenMsg, ErrInvalidRequest)
	}

	tokenPair, err := h.authUseCase.RefreshTokens(ctx, req.RefreshToken)
	if err != nil {
		log.Error(ctx, fmt.Sprintf("%s: %v", ErrRefreshTokensMsg, err))

		return nil, fmt.Errorf("%s: %w", ErrTokenRefreshFailedMsg, ErrInvalidToken)
	}

	return &authv1.RefreshTokensResponse{
		AccessToken:  tokenPair.AccessToken,
		RefreshToken: tokenPair.RefreshToken,
		ExpiresAt:    timestamppb.New(tokenPair.ExpiresAt),
	}, nil
}

// Logout выходит из системы.
func (h *AuthHandler) Logout(ctx context.Context, req *authv1.LogoutRequest) (*emptypb.Empty, error) {
	log := logger.Log(ctx)
	log.Info(ctx, LogLogoutRequest)

	if req.RefreshToken == "" {
		return nil, fmt.Errorf("%s: %w", ErrMissingRefreshLogoutMsg, ErrInvalidRequest)
	}

	err := h.authUseCase.Logout(ctx, req.RefreshToken)
	if err != nil {
		log.Error(ctx, fmt.Sprintf("%s: %v", ErrLogoutMsg, err))

		if err.Error() == ErrInvalidTokenMsg {
			return nil, fmt.Errorf("%s: %w", ErrLogoutFailedTokenMsg, ErrInvalidToken)
		}
		return nil, fmt.Errorf("%s: %w", ErrLogoutOperationFailedMsg, ErrAuthServiceInternal)
	}

	return &emptypb.Empty{}, nil
}

// RegisterService регистрирует AuthService в gRPC сервере.
func (h *AuthHandler) RegisterService(server *grpc.Server) {
	authv1.RegisterAuthServiceServer(server, h)
}
