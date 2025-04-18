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

func TestTokenRepository_CleanupExpiredTokens(t *testing.T) {
	ctx := context.Background()
	testLogger, err := logger.NewLogger(logger.Development, "debug")
	require.NoError(t, err)
	ctx = logger.NewContext(ctx, testLogger)

	t.Run("Успешная очистка токенов", func(t *testing.T) {
		mock, err := pgxmock.NewPool()
		require.NoError(t, err)
		defer mock.Close()

		mock.ExpectExec("DELETE FROM refresh_tokens").
			WillReturnResult(pgxmock.NewResult("DELETE", 5))

		repo := postgres.NewTokenRepository(mock)

		err = repo.CleanupExpiredTokens(ctx)

		require.NoError(t, err)

		err = mock.ExpectationsWereMet()
		require.NoError(t, err)
	})

	t.Run("Очистка без удаления токенов", func(t *testing.T) {
		mock, err := pgxmock.NewPool()
		require.NoError(t, err)
		defer mock.Close()

		mock.ExpectExec("DELETE FROM refresh_tokens").
			WillReturnResult(pgxmock.NewResult("DELETE", 0))

		repo := postgres.NewTokenRepository(mock)

		err = repo.CleanupExpiredTokens(ctx)

		require.NoError(t, err)

		err = mock.ExpectationsWereMet()
		require.NoError(t, err)
	})

	t.Run("Ошибка базы данных", func(t *testing.T) {
		mock, err := pgxmock.NewPool()
		require.NoError(t, err)
		defer mock.Close()

		dbError := errors.New("database connection failed")
		mock.ExpectExec("DELETE FROM refresh_tokens").
			WillReturnError(dbError)

		repo := postgres.NewTokenRepository(mock)

		err = repo.CleanupExpiredTokens(ctx)

		assert.Error(t, err)
		assert.Contains(t, err.Error(), "error cleaning up expired tokens")

		err = mock.ExpectationsWereMet()
		require.NoError(t, err)
	})
}
