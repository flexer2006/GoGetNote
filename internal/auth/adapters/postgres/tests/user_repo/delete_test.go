package userrepo_test

import (
	"context"
	"testing"

	"github.com/pashagolub/pgxmock/v4"
	"github.com/stretchr/testify/require"

	"gogetnote/internal/auth/adapters/postgres"
	"gogetnote/internal/auth/domain/entities"
	"gogetnote/pkg/logger"
)

const ErrDelUser = "error deleting user"

func TestUserRepository_Delete(t *testing.T) {
	ctx := context.Background()
	testLogger, err := logger.NewLogger(logger.Development, "debug")
	require.NoError(t, err)
	ctx = logger.NewContext(ctx, testLogger)

	const userID = "test-user-id"

	t.Run("successful user deletion", func(t *testing.T) {
		mock, err := pgxmock.NewPool()
		require.NoError(t, err)
		defer mock.Close()

		mock.ExpectExec("DELETE FROM users").
			WithArgs(userID).
			WillReturnResult(pgxmock.NewResult("DELETE", 1))

		repo := postgres.NewUserRepository(mock)

		err = repo.Delete(ctx, userID)

		require.NoError(t, err)

		err = mock.ExpectationsWereMet()
		require.NoError(t, err)
	})

	t.Run("the user was not found", func(t *testing.T) {
		mock, err := pgxmock.NewPool()
		require.NoError(t, err)
		defer mock.Close()

		mock.ExpectExec("DELETE FROM users").
			WithArgs(userID).
			WillReturnResult(pgxmock.NewResult("DELETE", 0))

		repo := postgres.NewUserRepository(mock)

		err = repo.Delete(ctx, userID)

		require.ErrorIs(t, err, entities.ErrUserNotFound)

		err = mock.ExpectationsWereMet()
		require.NoError(t, err)
	})

	t.Run("database error", func(t *testing.T) {
		mock, err := pgxmock.NewPool()
		require.NoError(t, err)
		defer mock.Close()

		mock.ExpectExec("DELETE FROM users").
			WithArgs(userID).
			WillReturnError(errDatabaseConnection)

		repo := postgres.NewUserRepository(mock)

		err = repo.Delete(ctx, userID)

		require.Error(t, err)
		require.Contains(t, err.Error(), ErrDelUser)

		err = mock.ExpectationsWereMet()
		require.NoError(t, err)
	})

	t.Run("empty User ID", func(t *testing.T) {
		mock, err := pgxmock.NewPool()
		require.NoError(t, err)
		defer mock.Close()

		mock.ExpectExec("DELETE FROM users").
			WithArgs("").
			WillReturnResult(pgxmock.NewResult("DELETE", 0))

		repo := postgres.NewUserRepository(mock)

		err = repo.Delete(ctx, "")

		require.ErrorIs(t, err, entities.ErrUserNotFound)

		err = mock.ExpectationsWereMet()
		require.NoError(t, err)
	})
}
