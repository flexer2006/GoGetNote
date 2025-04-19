package userrepo_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/pashagolub/pgxmock/v4"
	"github.com/stretchr/testify/require"

	"gogetnote/internal/auth/adapters/postgres"
	"gogetnote/internal/auth/domain/entities"
	"gogetnote/pkg/logger"
)

var ErrDatabaseConnection = errors.New("database connection failed")

const ErrQueryingUserByEmail = "error querying user by email"

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

	t.Run("successful receipt of the user by email", func(t *testing.T) {
		mock, err := pgxmock.NewPool()
		require.NoError(t, err)
		defer mock.Close()

		setupUserMock(mock, testUser.Email, testUser)

		repo := postgres.NewUserRepository(mock)

		user, err := repo.FindByEmail(ctx, testUser.Email)

		require.NoError(t, err)

		assertUserEquals(t, &testUser, user)

		err = mock.ExpectationsWereMet()
		require.NoError(t, err)
	})

	t.Run("the user was not found by email", func(t *testing.T) {
		mock, err := pgxmock.NewPool()
		require.NoError(t, err)
		defer mock.Close()

		nonExistingEmail := "nonexistent@example.com"
		mock.ExpectQuery("SELECT id, email, username, password_hash, created_at, updated_at").
			WithArgs(nonExistingEmail).
			WillReturnError(pgx.ErrNoRows)

		repo := postgres.NewUserRepository(mock)

		user, err := repo.FindByEmail(ctx, nonExistingEmail)

		require.Nil(t, user)
		require.ErrorIs(t, err, entities.ErrUserNotFound)

		err = mock.ExpectationsWereMet()
		require.NoError(t, err)
	})

	t.Run("database error when searching by email", func(t *testing.T) {
		mock, err := pgxmock.NewPool()
		require.NoError(t, err)
		defer mock.Close()

		mock.ExpectQuery("SELECT id, email, username, password_hash, created_at, updated_at").
			WithArgs(testUser.Email).
			WillReturnError(ErrDatabaseConnection)

		repo := postgres.NewUserRepository(mock)

		user, err := repo.FindByEmail(ctx, testUser.Email)

		require.Nil(t, user)
		require.Error(t, err)
		require.Contains(t, err.Error(), ErrQueryingUserByEmail)

		err = mock.ExpectationsWereMet()
		require.NoError(t, err)
	})

	t.Run("empty email", func(t *testing.T) {
		mock, err := pgxmock.NewPool()
		require.NoError(t, err)
		defer mock.Close()

		mock.ExpectQuery("SELECT id, email, username, password_hash, created_at, updated_at").
			WithArgs("").
			WillReturnError(pgx.ErrNoRows)

		repo := postgres.NewUserRepository(mock)

		user, err := repo.FindByEmail(ctx, "")

		require.Nil(t, user)
		require.ErrorIs(t, err, entities.ErrUserNotFound)

		err = mock.ExpectationsWereMet()
		require.NoError(t, err)
	})
}
