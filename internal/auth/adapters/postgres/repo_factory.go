package postgres

import (
	"github.com/jackc/pgx/v5/pgxpool"

	"gogetnote/internal/auth/ports/repositories"
)

// RepositoryFactory создает все необходимые репозитории для работы с PostgreSQL.
type RepositoryFactory struct {
	userRepo  repositories.UserRepository
	tokenRepo repositories.TokenRepository
}

// NewRepositoryFactory создает новую фабрику репозиториев.
func NewRepositoryFactory(pool *pgxpool.Pool) *RepositoryFactory {
	return &RepositoryFactory{
		userRepo:  NewUserRepository(pool),
		tokenRepo: NewTokenRepository(pool),
	}
}

// UserRepository возвращает репозиторий пользователей.
func (f *RepositoryFactory) UserRepository() repositories.UserRepository {
	return f.userRepo
}

// TokenRepository возвращает репозиторий токенов.
func (f *RepositoryFactory) TokenRepository() repositories.TokenRepository {
	return f.tokenRepo
}
