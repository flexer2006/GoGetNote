// Package grpc предоставляет реализацию gRPC сервера для аутентификационного сервиса.
package grpc

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"

	"go.uber.org/zap"
	"google.golang.org/protobuf/types/known/emptypb"
	"google.golang.org/protobuf/types/known/timestamppb"

	"gogetnote/internal/auth/ports/api"
	"gogetnote/internal/auth/ports/services"
	authv1 "gogetnote/pkg/api/auth/v1"
	"gogetnote/pkg/logger"
)

// Константы для логирования и кодов ошибок пользовательского сервиса.
const (
	LogGetUserProfileRequest     = "processing user profile request"
	ErrUserNotFoundMsg           = "user not found"
	ErrInternalServiceMsg        = "internal service error"
	ErrMissingUserIDMsg          = "user ID missing in context"
	ErrGetUserProfileMsg         = "error getting user profile"
	ErrProfileRetrievalFailedMsg = "profile retrieval failed"
	ErrUnauthorizedAccessMsg     = "unauthorized access"
	LogMetadataNotFoundMsg       = "failed to get metadata from context"
	LogAuthHeaderMissingMsg      = "authorization header missing"
	LogInvalidTokenFormatMsg     = "invalid token format in authorization header"
	LogInvalidAccessTokenMsg     = "invalid access token"
)

// Ошибки обработчика пользовательского сервиса.
var (
	ErrUserNotFound    = fmt.Errorf("%s", ErrUserNotFoundMsg)
	ErrInternalService = fmt.Errorf("%s", ErrInternalServiceMsg)
	ErrMissingUserID   = fmt.Errorf("%s", ErrMissingUserIDMsg)
)

// UserHandler реализует gRPC интерфейс UserService.
type UserHandler struct {
	userUseCase api.UserUseCase
	tokenSvc    services.TokenService
	authv1.UnimplementedUserServiceServer
}

// NewUserHandler создает новый обработчик UserService.
func NewUserHandler(userUseCase api.UserUseCase, tokenSvc services.TokenService) *UserHandler {
	return &UserHandler{
		userUseCase: userUseCase,
		tokenSvc:    tokenSvc,
	}
}

// GetUserProfile получает профиль текущего пользователя.
func (h *UserHandler) GetUserProfile(ctx context.Context, _ *emptypb.Empty) (*authv1.UserProfileResponse, error) {
	log := logger.Log(ctx)
	log.Info(ctx, LogGetUserProfileRequest)

	userID, ok := h.getUserIDFromContext(ctx)
	if !ok || userID == "" {
		log.Error(ctx, ErrMissingUserIDMsg)
		return nil, fmt.Errorf("%s: %w", ErrUnauthorizedAccessMsg, ErrMissingUserID)
	}

	user, err := h.userUseCase.GetUserProfile(ctx, userID)
	if err != nil {
		log.Error(ctx, fmt.Sprintf("%s: %v", ErrGetUserProfileMsg, err))
		if errors.Is(err, ErrUserNotFound) {
			return nil, fmt.Errorf("%s: %w", ErrProfileRetrievalFailedMsg, ErrUserNotFound)
		}
		return nil, fmt.Errorf("%s: %w", ErrProfileRetrievalFailedMsg, ErrInternalService)
	}

	return &authv1.UserProfileResponse{
		UserId:    user.ID,
		Email:     user.Email,
		Username:  user.Username,
		CreatedAt: timestamppb.New(user.CreatedAt),
	}, nil
}

// ServiceRegistrar это интерфейс, представляющий собой возможность регистрации сервиса.
type ServiceRegistrar interface {
	RegisterService(desc *grpc.ServiceDesc, impl any)
}

// RegisterService регистрирует UserService в gRPC сервере.
func (h *UserHandler) RegisterService(server ServiceRegistrar) {
	authv1.RegisterUserServiceServer(server, h)
}

// getUserIDFromContext извлекает идентификатор пользователя из контекста,
// используя JWT токен из метаданных запроса.
func (h *UserHandler) getUserIDFromContext(ctx context.Context) (string, bool) {
	log := logger.Log(ctx)

	mda, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		log.Debug(ctx, LogMetadataNotFoundMsg)
		return "", false
	}

	authHeader := mda.Get("authorization")
	if len(authHeader) == 0 {
		log.Debug(ctx, LogAuthHeaderMissingMsg)
		return "", false
	}

	tokenString := strings.TrimPrefix(authHeader[0], "Bearer ")
	if tokenString == authHeader[0] {
		log.Debug(ctx, LogInvalidTokenFormatMsg)
		return "", false
	}

	userID, err := h.tokenSvc.ValidateAccessToken(ctx, tokenString)
	if err != nil {
		log.Debug(ctx, LogInvalidAccessTokenMsg, zap.Error(err))
		return "", false
	}

	return userID, true
}
