package api

import (
	"context"

	"gogetnote/internal/auth/domain/entities"
)

// UserUseCase определяет основной порт для пользовательских операций
type UserUseCase interface {
	GetUserProfile(ctx context.Context, userID string) (*entities.User, error)
}
