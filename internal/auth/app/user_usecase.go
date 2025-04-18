package app

import (
	"context"
	"fmt"

	"gogetnote/internal/auth/domain/entities"
	"gogetnote/internal/auth/ports/api"
	"gogetnote/internal/auth/ports/repositories"
	"gogetnote/pkg/logger"

	"go.uber.org/zap"
)

const (
	methodGetUserProfile = "GetUserProfile"

	msgRequestingProfile   = "requesting user profile"
	msgEmptyUserIDProvided = "empty user ID provided"
	msgProfileRetrieved    = "user profile successfully retrieved"

	msgErrFindingUserByID = "failed to find user by ID"

	errCtxValidatingUserID = "validating user ID"
	errCtxFetchingProfile  = "fetching user profile"
)

// UserUseCaseImpl реализует интерфейс UserUseCase.
type UserUseCaseImpl struct {
	userRepo repositories.UserRepository
}

// NewUserUseCase создает новый экземпляр сервиса пользователя.
func NewUserUseCase(userRepo repositories.UserRepository) api.UserUseCase {
	return &UserUseCaseImpl{
		userRepo: userRepo,
	}
}

// GetUserProfile получает профиль пользователя по ID.
func (u *UserUseCaseImpl) GetUserProfile(ctx context.Context, userID string) (*entities.User, error) {
	log := logger.Log(ctx).With(zap.String("method", methodGetUserProfile), zap.String("userID", userID))
	log.Debug(ctx, msgRequestingProfile)

	if userID == "" {
		log.Debug(ctx, msgEmptyUserIDProvided)
		return nil, fmt.Errorf("%s: %w", errCtxValidatingUserID, entities.ErrEmptyUserID)
	}

	user, err := u.userRepo.FindByID(ctx, userID)
	if err != nil {
		log.Error(ctx, msgErrFindingUserByID, zap.Error(err))
		return nil, fmt.Errorf("%s: %w", errCtxFetchingProfile, err)
	}

	log.Info(ctx, msgProfileRetrieved)
	return user, nil
}
