package tokenrepo_test

import (
	"context"
	"errors"
	"testing"

	"github.com/pashagolub/pgxmock/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"gogetnote/internal/auth/adapters/postgres"
	"gogetnote/pkg/logger"
)

func TestTokenRepository_RevokeAllUserTokens(t *testing.T) {
	ctx := context.Background()
	testLogger, err := logger.NewLogger(logger.Development, "debug")
	require.NoError(t, err)
	ctx = logger.NewContext(ctx, testLogger)

	const userID = "test-user-id"

	t.Run("Успешная отмена всех токенов пользователя", func(t *testing.T) {
		mock, err := pgxmock.NewPool()
		require.NoError(t, err)
		defer mock.Close()

		mock.ExpectExec("UPDATE refresh_tokens").
			WithArgs(userID).
			WillReturnResult(pgxmock.NewResult("UPDATE", 3))

		repo := postgres.NewTokenRepository(mock)

		err = repo.RevokeAllUserTokens(ctx, userID)

		require.NoError(t, err)

		err = mock.ExpectationsWereMet()
		require.NoError(t, err)
	})

	t.Run("Отмена токенов - нет активных токенов", func(t *testing.T) {
		mock, err := pgxmock.NewPool()
		require.NoError(t, err)
		defer mock.Close()

		mock.ExpectExec("UPDATE refresh_tokens").
			WithArgs(userID).
			WillReturnResult(pgxmock.NewResult("UPDATE", 0))

		repo := postgres.NewTokenRepository(mock)

		err = repo.RevokeAllUserTokens(ctx, userID)

		require.NoError(t, err)

		err = mock.ExpectationsWereMet()
		require.NoError(t, err)
	})

	t.Run("Ошибка базы данных", func(t *testing.T) {
		mock, err := pgxmock.NewPool()
		require.NoError(t, err)
		defer mock.Close()

		dbError := errors.New("database connection failed")
		mock.ExpectExec("UPDATE refresh_tokens").
			WithArgs(userID).
			WillReturnError(dbError)

		repo := postgres.NewTokenRepository(mock)

		err = repo.RevokeAllUserTokens(ctx, userID)

		assert.Error(t, err)
		assert.Contains(t, err.Error(), "error revoking all user tokens")

		err = mock.ExpectationsWereMet()
		require.NoError(t, err)
	})

	t.Run("Пустой ID пользователя", func(t *testing.T) {
		mock, err := pgxmock.NewPool()
		require.NoError(t, err)
		defer mock.Close()

		mock.ExpectExec("UPDATE refresh_tokens").
			WithArgs("").
			WillReturnResult(pgxmock.NewResult("UPDATE", 0))

		repo := postgres.NewTokenRepository(mock)

		err = repo.RevokeAllUserTokens(ctx, "")

		require.NoError(t, err)

		err = mock.ExpectationsWereMet()
		require.NoError(t, err)
	})
}
