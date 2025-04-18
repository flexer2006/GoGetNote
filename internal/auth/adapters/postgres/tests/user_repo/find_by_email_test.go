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

func TestUserRepository_FindByEmail(t *testing.T) {
	ctx := context.Background()
	testLogger, err := logger.NewLogger(logger.Development, "debug")
	require.NoError(t, err)
	ctx = logger.NewContext(ctx, testLogger)

	testUser := entities.User{
		ID:           "test-user-id",
		Email:        "test@example.com",
		Username:     "testuser",
		PasswordHash: "hashed_password",
		CreatedAt:    time.Now().UTC().Truncate(time.Microsecond),
		UpdatedAt:    time.Now().UTC().Truncate(time.Microsecond),
	}

	t.Run("Успешное получение пользователя по email", func(t *testing.T) {
		mock, err := pgxmock.NewPool()
		require.NoError(t, err)
		defer mock.Close()

		rows := pgxmock.NewRows([]string{"id", "email", "username", "password_hash", "created_at", "updated_at"}).
			AddRow(testUser.ID, testUser.Email, testUser.Username, testUser.PasswordHash, testUser.CreatedAt, testUser.UpdatedAt)

		mock.ExpectQuery("SELECT id, email, username, password_hash, created_at, updated_at").
			WithArgs(testUser.Email).
			WillReturnRows(rows)

		repo := postgres.NewUserRepository(mock)

		user, err := repo.FindByEmail(ctx, testUser.Email)

		require.NoError(t, err)
		assert.Equal(t, testUser.ID, user.ID)
		assert.Equal(t, testUser.Email, user.Email)
		assert.Equal(t, testUser.Username, user.Username)
		assert.Equal(t, testUser.PasswordHash, user.PasswordHash)
		assert.Equal(t, testUser.CreatedAt, user.CreatedAt)
		assert.Equal(t, testUser.UpdatedAt, user.UpdatedAt)

		err = mock.ExpectationsWereMet()
		require.NoError(t, err)
	})

	t.Run("Пользователь не найден по email", func(t *testing.T) {
		mock, err := pgxmock.NewPool()
		require.NoError(t, err)
		defer mock.Close()

		nonExistingEmail := "nonexistent@example.com"
		mock.ExpectQuery("SELECT id, email, username, password_hash, created_at, updated_at").
			WithArgs(nonExistingEmail).
			WillReturnError(pgx.ErrNoRows)

		repo := postgres.NewUserRepository(mock)

		user, err := repo.FindByEmail(ctx, nonExistingEmail)

		assert.Nil(t, user)
		assert.ErrorIs(t, err, entities.ErrUserNotFound)

		err = mock.ExpectationsWereMet()
		require.NoError(t, err)
	})

	t.Run("Ошибка базы данных при поиске по email", func(t *testing.T) {
		mock, err := pgxmock.NewPool()
		require.NoError(t, err)
		defer mock.Close()

		dbError := errors.New("database connection failed")
		mock.ExpectQuery("SELECT id, email, username, password_hash, created_at, updated_at").
			WithArgs(testUser.Email).
			WillReturnError(dbError)

		repo := postgres.NewUserRepository(mock)

		user, err := repo.FindByEmail(ctx, testUser.Email)

		assert.Nil(t, user)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "error querying user by email")

		err = mock.ExpectationsWereMet()
		require.NoError(t, err)
	})

	t.Run("Пустой email", func(t *testing.T) {
		mock, err := pgxmock.NewPool()
		require.NoError(t, err)
		defer mock.Close()

		mock.ExpectQuery("SELECT id, email, username, password_hash, created_at, updated_at").
			WithArgs("").
			WillReturnError(pgx.ErrNoRows)

		repo := postgres.NewUserRepository(mock)

		user, err := repo.FindByEmail(ctx, "")

		assert.Nil(t, user)
		assert.ErrorIs(t, err, entities.ErrUserNotFound)

		err = mock.ExpectationsWereMet()
		require.NoError(t, err)
	})
}
