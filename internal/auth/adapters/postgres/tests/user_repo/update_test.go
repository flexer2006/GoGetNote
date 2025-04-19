package userrepo_test

import (
	"context"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/pashagolub/pgxmock/v4"
	"github.com/stretchr/testify/require"

	"gogetnote/internal/auth/adapters/postgres"
	"gogetnote/internal/auth/domain/entities"
	"gogetnote/pkg/logger"
)

const ErrUpdatingUser = "error updating user"

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

	t.Run("Successful user update", func(t *testing.T) {
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
		assertUserEquals(t, &expectedUser, updatedUser)

		err = mock.ExpectationsWereMet()
		require.NoError(t, err)
	})

	t.Run("The user was not found", func(t *testing.T) {
		mock, err := pgxmock.NewPool()
		require.NoError(t, err)
		defer mock.Close()

		mock.ExpectQuery("UPDATE users").
			WithArgs(user.ID, user.Email, user.Username, user.PasswordHash, pgxmock.AnyArg()).
			WillReturnError(pgx.ErrNoRows)

		repo := postgres.NewUserRepository(mock)
		updatedUser, err := repo.Update(ctx, user)

		require.ErrorIs(t, err, entities.ErrUserNotFound)
		require.Nil(t, updatedUser)

		err = mock.ExpectationsWereMet()
		require.NoError(t, err)
	})

	t.Run("Database error", func(t *testing.T) {
		mock, err := pgxmock.NewPool()
		require.NoError(t, err)
		defer mock.Close()

		mock.ExpectQuery("UPDATE users").
			WithArgs(user.ID, user.Email, user.Username, user.PasswordHash, pgxmock.AnyArg()).
			WillReturnError(ErrDatabaseConnection)

		repo := postgres.NewUserRepository(mock)
		updatedUser, err := repo.Update(ctx, user)

		require.Nil(t, updatedUser)
		require.Error(t, err)
		require.Contains(t, err.Error(), ErrUpdatingUser)

		err = mock.ExpectationsWereMet()
		require.NoError(t, err)
	})

	t.Run("Empty User ID", func(t *testing.T) {
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

		require.ErrorIs(t, err, entities.ErrUserNotFound)
		require.Nil(t, updatedUser)

		err = mock.ExpectationsWereMet()
		require.NoError(t, err)
	})
}
