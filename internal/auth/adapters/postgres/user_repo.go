// Package postgres предоставляет реализацию репозиториев для работы с базой данных Postgres.
// Он содержит функции и структуры для выполнения CRUD операций над сущностями аутентификации.
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

// Константы сообщений журнала и ошибок.
const (
	msgUserNotFound            = "user not found"
	msgUserNotFoundForUpdate   = "user not found for update"
	msgUserNotFoundForDeletion = "user not found for deletion"
	msgErrorFindingUser        = "error finding user by "
	msgErrorCreatingUser       = "error creating user"
	msgErrorUpdatingUser       = "error updating user"
	msgErrorDeletingUser       = "error deleting user"

	errMsgQueryingUser = "error querying user by "
	errMsgCreatingUser = "error creating user"
	errMsgUpdatingUser = "error updating user"
	errMsgDeletingUser = "error deleting user"
)

// PgxPoolInterface определяет интерфейс для работы с пулом соединений Postgres.
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

// findUser выполняет базовые операции поиска пользователя по условию.
func (r *UserRepository) findUser(ctx context.Context, query string, fieldName string, fieldValue string, logMethod string) (*entities.User, error) {
	log := logger.Log(ctx).With(zap.String("repository", "user"), zap.String("method", logMethod))

	var user entities.User
	err := r.pool.QueryRow(ctx, query, fieldValue).Scan(
		&user.ID,
		&user.Email,
		&user.Username,
		&user.PasswordHash,
		&user.CreatedAt,
		&user.UpdatedAt,
	)

	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			log.Debug(ctx, msgUserNotFound, zap.String(fieldName, fieldValue))
			return nil, entities.ErrUserNotFound
		}
		log.Error(ctx, msgErrorFindingUser+fieldName, zap.Error(err))
		return nil, fmt.Errorf(errMsgQueryingUser+"%s: %w", fieldName, err)
	}

	return &user, nil
}

// FindByID находит пользователя по ID.
func (r *UserRepository) FindByID(ctx context.Context, idn string) (*entities.User, error) {
	query := `
        SELECT id, email, username, password_hash, created_at, updated_at
        FROM users
        WHERE id = $1
    `
	return r.findUser(ctx, query, "id", idn, "FindByID")
}

// FindByEmail находит пользователя по email.
func (r *UserRepository) FindByEmail(ctx context.Context, email string) (*entities.User, error) {
	query := `
        SELECT id, email, username, password_hash, created_at, updated_at
        FROM users
        WHERE email = $1
    `
	return r.findUser(ctx, query, "email", email, "FindByEmail")
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
		log.Error(ctx, msgErrorCreatingUser, zap.Error(err))
		return nil, fmt.Errorf("%s: %w", errMsgCreatingUser, err)
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
			log.Debug(ctx, msgUserNotFoundForUpdate, zap.String("id", user.ID))
			return nil, entities.ErrUserNotFound
		}
		log.Error(ctx, msgErrorUpdatingUser, zap.Error(err))
		return nil, fmt.Errorf("%s: %w", errMsgUpdatingUser, err)
	}

	return &updatedUser, nil
}

// Delete удаляет пользователя по ID.
func (r *UserRepository) Delete(ctx context.Context, idn string) error {
	log := logger.Log(ctx).With(zap.String("repository", "user"), zap.String("method", "Delete"))

	query := `
        DELETE FROM users
        WHERE id = $1
    `

	result, err := r.pool.Exec(ctx, query, idn)
	if err != nil {
		log.Error(ctx, msgErrorDeletingUser, zap.Error(err))
		return fmt.Errorf("%s: %w", errMsgDeletingUser, err)
	}

	if result.RowsAffected() == 0 {
		log.Debug(ctx, msgUserNotFoundForDeletion, zap.String("id", idn))
		return entities.ErrUserNotFound
	}

	return nil
}
