package repositories

import (
	"context"

	"gogetnote/internal/auth/domain/entities"
)

// UserRepository определяет интерфейс для операций сохранения данных пользователем.
type UserRepository interface {
	Create(ctx context.Context, user *entities.User) (*entities.User, error)

	FindByID(ctx context.Context, id string) (*entities.User, error)

	FindByEmail(ctx context.Context, email string) (*entities.User, error)

	Update(ctx context.Context, user *entities.User) (*entities.User, error)

	Delete(ctx context.Context, id string) error
}
