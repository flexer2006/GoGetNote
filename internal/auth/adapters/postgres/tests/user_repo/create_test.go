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

var (
	errDatabaseConnection = errors.New("database connection error")
	errDuplicateKey       = errors.New("duplicate key value violates unique constraint")
)

const ErrCreatingUser = "error creating user"

func assertUserEquals(t *testing.T, expected, actual *entities.User) {
	t.Helper()
	require.NotNil(t, actual)
	assert.Equal(t, expected.ID, actual.ID)
	assert.Equal(t, expected.Email, actual.Email)
	assert.Equal(t, expected.Username, actual.Username)
	assert.Equal(t, expected.PasswordHash, actual.PasswordHash)
	assert.Equal(t, expected.CreatedAt, actual.CreatedAt)
	assert.Equal(t, expected.UpdatedAt, actual.UpdatedAt)
}

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

	t.Run("successful user creation", func(t *testing.T) {
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
		assertUserEquals(t, &expectedUser, createdUser)

		err = mock.ExpectationsWereMet()
		require.NoError(t, err)
	})

	t.Run("error when creating a user is a common database error", func(t *testing.T) {
		mock, err := pgxmock.NewPool()
		require.NoError(t, err)
		defer mock.Close()

		mock.ExpectQuery("INSERT INTO users .+").
			WithArgs(inputUser.Email, inputUser.Username, inputUser.PasswordHash).
			WillReturnError(errDatabaseConnection)

		repo := postgres.NewUserRepository(mock)
		createdUser, err := repo.Create(ctx, inputUser)

		require.Nil(t, createdUser)
		require.Error(t, err)
		require.Contains(t, err.Error(), ErrCreatingUser)

		err = mock.ExpectationsWereMet()
		require.NoError(t, err)
	})

	t.Run("error when creating a user - duplicate email", func(t *testing.T) {
		mock, err := pgxmock.NewPool()
		require.NoError(t, err)
		defer mock.Close()

		mock.ExpectQuery("INSERT INTO users .+").
			WithArgs(inputUser.Email, inputUser.Username, inputUser.PasswordHash).
			WillReturnError(errDuplicateKey)

		repo := postgres.NewUserRepository(mock)
		createdUser, err := repo.Create(ctx, inputUser)

		require.Nil(t, createdUser)
		require.Error(t, err)
		require.Contains(t, err.Error(), ErrCreatingUser)

		err = mock.ExpectationsWereMet()
		require.NoError(t, err)
	})

	t.Run("creating a user with minimal data", func(t *testing.T) {
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
		assertUserEquals(t, &expectedMinimalUser, createdUser)

		err = mock.ExpectationsWereMet()
		require.NoError(t, err)
	})
}
