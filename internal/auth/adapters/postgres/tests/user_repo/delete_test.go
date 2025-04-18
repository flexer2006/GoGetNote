package userrepo_test

import (
	"context"
	"errors"
	"testing"

	"github.com/pashagolub/pgxmock/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"gogetnote/internal/auth/adapters/postgres"
	"gogetnote/internal/auth/domain/entities"
	"gogetnote/pkg/logger"
)

func TestUserRepository_Delete(t *testing.T) {
	ctx := context.Background()
	testLogger, err := logger.NewLogger(logger.Development, "debug")
	require.NoError(t, err)
	ctx = logger.NewContext(ctx, testLogger)

	const userID = "test-user-id"

	t.Run("Успешное удаление пользователя", func(t *testing.T) {
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

	t.Run("Пользователь не найден", func(t *testing.T) {
		mock, err := pgxmock.NewPool()
		require.NoError(t, err)
		defer mock.Close()

		mock.ExpectExec("DELETE FROM users").
			WithArgs(userID).
			WillReturnResult(pgxmock.NewResult("DELETE", 0))

		repo := postgres.NewUserRepository(mock)

		err = repo.Delete(ctx, userID)

		assert.ErrorIs(t, err, entities.ErrUserNotFound)

		err = mock.ExpectationsWereMet()
		require.NoError(t, err)
	})

	t.Run("Ошибка базы данных", func(t *testing.T) {
		mock, err := pgxmock.NewPool()
		require.NoError(t, err)
		defer mock.Close()

		dbError := errors.New("database connection failed")
		mock.ExpectExec("DELETE FROM users").
			WithArgs(userID).
			WillReturnError(dbError)

		repo := postgres.NewUserRepository(mock)

		err = repo.Delete(ctx, userID)

		assert.Error(t, err)
		assert.Contains(t, err.Error(), "error deleting user")

		err = mock.ExpectationsWereMet()
		require.NoError(t, err)
	})

	t.Run("Пустой ID пользователя", func(t *testing.T) {
		mock, err := pgxmock.NewPool()
		require.NoError(t, err)
		defer mock.Close()

		mock.ExpectExec("DELETE FROM users").
			WithArgs("").
			WillReturnResult(pgxmock.NewResult("DELETE", 0))

		repo := postgres.NewUserRepository(mock)

		err = repo.Delete(ctx, "")

		assert.ErrorIs(t, err, entities.ErrUserNotFound)

		err = mock.ExpectationsWereMet()
		require.NoError(t, err)
	})
}
