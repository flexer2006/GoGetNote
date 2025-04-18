package userrepo_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/pashagolub/pgxmock/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"gogetnote/internal/auth/adapters/postgres"
	"gogetnote/internal/auth/domain/entities"
	"gogetnote/pkg/logger"
)

func TestUserRepository_Create(t *testing.T) {
	ctx := context.Background()
	testLogger, err := logger.NewLogger(logger.Development, "debug")
	require.NoError(t, err)
	ctx = logger.NewContext(ctx, testLogger)

	inputUser := &entities.User{
		Email:        "new@example.com",
		Username:     "newuser",
		PasswordHash: "hashed_new_password",
	}

	expectedUser := entities.User{
		ID:           "generated-uuid",
		Email:        inputUser.Email,
		Username:     inputUser.Username,
		PasswordHash: inputUser.PasswordHash,
		CreatedAt:    time.Now().UTC().Truncate(time.Microsecond),
		UpdatedAt:    time.Now().UTC().Truncate(time.Microsecond),
	}

	t.Run("Успешное создание пользователя", func(t *testing.T) {
		mock, err := pgxmock.NewPool()
		require.NoError(t, err)
		defer mock.Close()

		mock.ExpectQuery("INSERT INTO users .+").
			WithArgs(inputUser.Email, inputUser.Username, inputUser.PasswordHash).
			WillReturnRows(
				pgxmock.NewRows([]string{"id", "email", "username", "password_hash", "created_at", "updated_at"}).
					AddRow(expectedUser.ID, expectedUser.Email, expectedUser.Username, expectedUser.PasswordHash, expectedUser.CreatedAt, expectedUser.UpdatedAt),
			)

		repo := postgres.NewUserRepository(mock)
		createdUser, err := repo.Create(ctx, inputUser)

		require.NoError(t, err)
		assert.NotNil(t, createdUser)
		assert.Equal(t, expectedUser.ID, createdUser.ID)
		assert.Equal(t, expectedUser.Email, createdUser.Email)
		assert.Equal(t, expectedUser.Username, createdUser.Username)
		assert.Equal(t, expectedUser.PasswordHash, createdUser.PasswordHash)
		assert.Equal(t, expectedUser.CreatedAt, createdUser.CreatedAt)
		assert.Equal(t, expectedUser.UpdatedAt, createdUser.UpdatedAt)

		err = mock.ExpectationsWereMet()
		require.NoError(t, err)
	})

	t.Run("Ошибка при создании пользователя - общая ошибка БД", func(t *testing.T) {
		mock, err := pgxmock.NewPool()
		require.NoError(t, err)
		defer mock.Close()

		dbError := errors.New("database connection error")
		mock.ExpectQuery("INSERT INTO users .+").
			WithArgs(inputUser.Email, inputUser.Username, inputUser.PasswordHash).
			WillReturnError(dbError)

		repo := postgres.NewUserRepository(mock)
		createdUser, err := repo.Create(ctx, inputUser)

		assert.Nil(t, createdUser)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "error creating user")

		err = mock.ExpectationsWereMet()
		require.NoError(t, err)
	})

	t.Run("Ошибка при создании пользователя - дублирующийся email", func(t *testing.T) {
		mock, err := pgxmock.NewPool()
		require.NoError(t, err)
		defer mock.Close()

		duplicateErr := errors.New("duplicate key value violates unique constraint")
		mock.ExpectQuery("INSERT INTO users .+").
			WithArgs(inputUser.Email, inputUser.Username, inputUser.PasswordHash).
			WillReturnError(duplicateErr)

		repo := postgres.NewUserRepository(mock)
		createdUser, err := repo.Create(ctx, inputUser)

		assert.Nil(t, createdUser)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "error creating user")

		err = mock.ExpectationsWereMet()
		require.NoError(t, err)
	})

	t.Run("Создание пользователя с минимальными данными", func(t *testing.T) {
		mock, err := pgxmock.NewPool()
		require.NoError(t, err)
		defer mock.Close()

		minimalUser := &entities.User{
			Email:        "minimal@example.com",
			Username:     "minimal",
			PasswordHash: "hash",
		}

		expectedMinimalUser := entities.User{
			ID:           "generated-minimal-uuid",
			Email:        minimalUser.Email,
			Username:     minimalUser.Username,
			PasswordHash: minimalUser.PasswordHash,
			CreatedAt:    time.Now().UTC().Truncate(time.Microsecond),
			UpdatedAt:    time.Now().UTC().Truncate(time.Microsecond),
		}

		mock.ExpectQuery("INSERT INTO users .+").
			WithArgs(minimalUser.Email, minimalUser.Username, minimalUser.PasswordHash).
			WillReturnRows(
				pgxmock.NewRows([]string{"id", "email", "username", "password_hash", "created_at", "updated_at"}).
					AddRow(expectedMinimalUser.ID, expectedMinimalUser.Email, expectedMinimalUser.Username,
						expectedMinimalUser.PasswordHash, expectedMinimalUser.CreatedAt, expectedMinimalUser.UpdatedAt),
			)

		repo := postgres.NewUserRepository(mock)
		createdUser, err := repo.Create(ctx, minimalUser)

		require.NoError(t, err)
		assert.Equal(t, expectedMinimalUser.Email, createdUser.Email)
		assert.Equal(t, expectedMinimalUser.Username, createdUser.Username)
		assert.NotEmpty(t, createdUser.ID)

		err = mock.ExpectationsWereMet()
		require.NoError(t, err)
	})
}
