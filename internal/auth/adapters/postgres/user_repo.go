package postgres

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"go.uber.org/zap"

	"gogetnote/internal/auth/domain/entities"
	"gogetnote/internal/auth/ports/repositories"
	"gogetnote/pkg/logger"
)

type PgxPoolInterface interface {
	QueryRow(ctx context.Context, query string, args ...interface{}) pgx.Row
	Exec(ctx context.Context, query string, args ...interface{}) (pgconn.CommandTag, error)
	Query(ctx context.Context, query string, args ...interface{}) (pgx.Rows, error)
	Begin(ctx context.Context) (pgx.Tx, error)
	Close()
}

// UserRepository реализует интерфейс repositories.UserRepository для работы с Postgres.
type UserRepository struct {
	pool PgxPoolInterface
}

// NewUserRepository создает новый экземпляр репозитория пользователей.
func NewUserRepository(pool PgxPoolInterface) repositories.UserRepository {
	return &UserRepository{pool: pool}
}

// FindByID находит пользователя по ID.
func (r *UserRepository) FindByID(ctx context.Context, id string) (*entities.User, error) {
	log := logger.Log(ctx).With(zap.String("repository", "user"), zap.String("method", "FindByID"))

	query := `
        SELECT id, email, username, password_hash, created_at, updated_at
        FROM users
        WHERE id = $1
    `

	var user entities.User
	err := r.pool.QueryRow(ctx, query, id).Scan(
		&user.ID,
		&user.Email,
		&user.Username,
		&user.PasswordHash,
		&user.CreatedAt,
		&user.UpdatedAt,
	)

	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			log.Debug(ctx, "user not found", zap.String("id", id))
			return nil, entities.ErrUserNotFound
		}
		log.Error(ctx, "error finding user by id", zap.Error(err))
		return nil, fmt.Errorf("error querying user by id: %w", err)
	}

	return &user, nil
}

// FindByEmail находит пользователя по email.
func (r *UserRepository) FindByEmail(ctx context.Context, email string) (*entities.User, error) {
	log := logger.Log(ctx).With(zap.String("repository", "user"), zap.String("method", "FindByEmail"))

	query := `
        SELECT id, email, username, password_hash, created_at, updated_at
        FROM users
        WHERE email = $1
    `

	var user entities.User
	err := r.pool.QueryRow(ctx, query, email).Scan(
		&user.ID,
		&user.Email,
		&user.Username,
		&user.PasswordHash,
		&user.CreatedAt,
		&user.UpdatedAt,
	)

	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			log.Debug(ctx, "user not found", zap.String("email", email))
			return nil, entities.ErrUserNotFound
		}
		log.Error(ctx, "error finding user by email", zap.Error(err))
		return nil, fmt.Errorf("error querying user by email: %w", err)
	}

	return &user, nil
}

// Create создает нового пользователя.
func (r *UserRepository) Create(ctx context.Context, user *entities.User) (*entities.User, error) {
	log := logger.Log(ctx).With(zap.String("repository", "user"), zap.String("method", "Create"))

	query := `
        INSERT INTO users (email, username, password_hash)
        VALUES ($1, $2, $3)
        RETURNING id, email, username, password_hash, created_at, updated_at
    `

	var createdUser entities.User
	err := r.pool.QueryRow(ctx, query,
		user.Email,
		user.Username,
		user.PasswordHash,
	).Scan(
		&createdUser.ID,
		&createdUser.Email,
		&createdUser.Username,
		&createdUser.PasswordHash,
		&createdUser.CreatedAt,
		&createdUser.UpdatedAt,
	)

	if err != nil {
		log.Error(ctx, "error creating user", zap.Error(err))
		return nil, fmt.Errorf("error creating user: %w", err)
	}

	return &createdUser, nil
}

// Update обновляет информацию о пользователе.
func (r *UserRepository) Update(ctx context.Context, user *entities.User) (*entities.User, error) {
	log := logger.Log(ctx).With(zap.String("repository", "user"), zap.String("method", "Update"))

	query := `
        UPDATE users
        SET email = $2, username = $3, password_hash = $4, updated_at = $5
        WHERE id = $1
        RETURNING id, email, username, password_hash, created_at, updated_at
    `

	var updatedUser entities.User
	now := time.Now().UTC() // Use UTC time instead of local time

	err := r.pool.QueryRow(ctx, query,
		user.ID,
		user.Email,
		user.Username,
		user.PasswordHash,
		now,
	).Scan(
		&updatedUser.ID,
		&updatedUser.Email,
		&updatedUser.Username,
		&updatedUser.PasswordHash,
		&updatedUser.CreatedAt,
		&updatedUser.UpdatedAt,
	)

	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			log.Debug(ctx, "user not found for update", zap.String("id", user.ID))
			return nil, entities.ErrUserNotFound
		}
		log.Error(ctx, "error updating user", zap.Error(err))
		return nil, fmt.Errorf("error updating user: %w", err)
	}

	return &updatedUser, nil
}

// Delete удаляет пользователя по ID.
func (r *UserRepository) Delete(ctx context.Context, id string) error {
	log := logger.Log(ctx).With(zap.String("repository", "user"), zap.String("method", "Delete"))

	query := `
        DELETE FROM users
        WHERE id = $1
    `

	result, err := r.pool.Exec(ctx, query, id)
	if err != nil {
		log.Error(ctx, "error deleting user", zap.Error(err))
		return fmt.Errorf("error deleting user: %w", err)
	}

	if result.RowsAffected() == 0 {
		log.Debug(ctx, "user not found for deletion", zap.String("id", id))
		return entities.ErrUserNotFound
	}

	return nil
}
