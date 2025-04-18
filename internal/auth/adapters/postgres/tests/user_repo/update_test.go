package userrepo_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/pashagolub/pgxmock/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"gogetnote/internal/auth/adapters/postgres"
	"gogetnote/internal/auth/domain/entities"
	"gogetnote/pkg/logger"
)

func TestUserRepository_Update(t *testing.T) {
	ctx := context.Background()
	testLogger, err := logger.NewLogger(logger.Development, "debug")
	require.NoError(t, err)
	ctx = logger.NewContext(ctx, testLogger)

	user := &entities.User{
		ID:           "existing-user-id",
		Email:        "updated@example.com",
		Username:     "updateduser",
		PasswordHash: "updated_password_hash",
	}

	expectedUser := entities.User{
		ID:           user.ID,
		Email:        user.Email,
		Username:     user.Username,
		PasswordHash: user.PasswordHash,
		CreatedAt:    time.Now().UTC().Truncate(time.Microsecond),
		UpdatedAt:    time.Now().UTC().Add(time.Second).Truncate(time.Microsecond),
	}

	t.Run("Успешное обновление пользователя", func(t *testing.T) {
		mock, err := pgxmock.NewPool()
		require.NoError(t, err)
		defer mock.Close()

		mock.ExpectQuery("UPDATE users SET email = \\$2, username = \\$3, password_hash = \\$4, updated_at = \\$5 WHERE id = \\$1").
			WithArgs(user.ID, user.Email, user.Username, user.PasswordHash, pgxmock.AnyArg()).
			WillReturnRows(
				pgxmock.NewRows([]string{"id", "email", "username", "password_hash", "created_at", "updated_at"}).
					AddRow(expectedUser.ID, expectedUser.Email, expectedUser.Username, expectedUser.PasswordHash, expectedUser.CreatedAt, expectedUser.UpdatedAt),
			)

		repo := postgres.NewUserRepository(mock)
		updatedUser, err := repo.Update(ctx, user)

		require.NoError(t, err)
		assert.NotNil(t, updatedUser)
		assert.Equal(t, expectedUser.ID, updatedUser.ID)
		assert.Equal(t, expectedUser.Email, updatedUser.Email)
		assert.Equal(t, expectedUser.Username, updatedUser.Username)
		assert.Equal(t, expectedUser.PasswordHash, updatedUser.PasswordHash)

		assert.NotZero(t, updatedUser.CreatedAt)
		assert.NotZero(t, updatedUser.UpdatedAt)

		err = mock.ExpectationsWereMet()
		require.NoError(t, err)
	})

	t.Run("Пользователь не найден", func(t *testing.T) {
		mock, err := pgxmock.NewPool()
		require.NoError(t, err)
		defer mock.Close()

		mock.ExpectQuery("UPDATE users").
			WithArgs(user.ID, user.Email, user.Username, user.PasswordHash, pgxmock.AnyArg()).
			WillReturnError(pgx.ErrNoRows)

		repo := postgres.NewUserRepository(mock)
		updatedUser, err := repo.Update(ctx, user)

		assert.ErrorIs(t, err, entities.ErrUserNotFound)
		assert.Nil(t, updatedUser)

		err = mock.ExpectationsWereMet()
		require.NoError(t, err)
	})

	t.Run("Ошибка базы данных", func(t *testing.T) {
		mock, err := pgxmock.NewPool()
		require.NoError(t, err)
		defer mock.Close()

		dbError := errors.New("database connection failed")
		mock.ExpectQuery("UPDATE users").
			WithArgs(user.ID, user.Email, user.Username, user.PasswordHash, pgxmock.AnyArg()).
			WillReturnError(dbError)

		repo := postgres.NewUserRepository(mock)
		updatedUser, err := repo.Update(ctx, user)

		assert.Nil(t, updatedUser)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "error updating user")

		err = mock.ExpectationsWereMet()
		require.NoError(t, err)
	})

	t.Run("Пустой ID пользователя", func(t *testing.T) {
		mock, err := pgxmock.NewPool()
		require.NoError(t, err)
		defer mock.Close()

		userWithEmptyID := &entities.User{
			ID:           "",
			Email:        "updated@example.com",
			Username:     "updateduser",
			PasswordHash: "updated_password_hash",
		}

		mock.ExpectQuery("UPDATE users").
			WithArgs(userWithEmptyID.ID, userWithEmptyID.Email, userWithEmptyID.Username, userWithEmptyID.PasswordHash, pgxmock.AnyArg()).
			WillReturnError(pgx.ErrNoRows)

		repo := postgres.NewUserRepository(mock)
		updatedUser, err := repo.Update(ctx, userWithEmptyID)

		assert.ErrorIs(t, err, entities.ErrUserNotFound)
		assert.Nil(t, updatedUser)

		err = mock.ExpectationsWereMet()
		require.NoError(t, err)
	})
}
