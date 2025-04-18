package tokenrepo_test

import (
	"context"
	"errors"
	"testing"

	"github.com/pashagolub/pgxmock/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"gogetnote/internal/auth/adapters/postgres"
	"gogetnote/internal/auth/domain/services"
	"gogetnote/pkg/logger"
)

func TestTokenRepository_RevokeToken(t *testing.T) {
	ctx := context.Background()
	testLogger, err := logger.NewLogger(logger.Development, "debug")
	require.NoError(t, err)
	ctx = logger.NewContext(ctx, testLogger)

	const tokenValue = "test-token-value"

	t.Run("Успешная отмена токена", func(t *testing.T) {

		mock, err := pgxmock.NewPool()
		require.NoError(t, err)
		defer mock.Close()

		mock.ExpectExec("UPDATE refresh_tokens").
			WithArgs(tokenValue).
			WillReturnResult(pgxmock.NewResult("UPDATE", 1))

		repo := postgres.NewTokenRepository(mock)

		err = repo.RevokeToken(ctx, tokenValue)

		require.NoError(t, err)

		err = mock.ExpectationsWereMet()
		require.NoError(t, err)
	})

	t.Run("Токен не найден", func(t *testing.T) {

		mock, err := pgxmock.NewPool()
		require.NoError(t, err)
		defer mock.Close()

		mock.ExpectExec("UPDATE refresh_tokens").
			WithArgs(tokenValue).
			WillReturnResult(pgxmock.NewResult("UPDATE", 0))

		repo := postgres.NewTokenRepository(mock)

		err = repo.RevokeToken(ctx, tokenValue)

		assert.ErrorIs(t, err, services.ErrInvalidRefreshToken)

		err = mock.ExpectationsWereMet()
		require.NoError(t, err)
	})

	t.Run("Ошибка базы данных", func(t *testing.T) {
		mock, err := pgxmock.NewPool()
		require.NoError(t, err)
		defer mock.Close()

		dbError := errors.New("database connection failed")
		mock.ExpectExec("UPDATE refresh_tokens").
			WithArgs(tokenValue).
			WillReturnError(dbError)

		repo := postgres.NewTokenRepository(mock)

		// Вызываем тестируемый метод
		err = repo.RevokeToken(ctx, tokenValue)

		assert.Error(t, err)
		assert.Contains(t, err.Error(), "error revoking refresh token")

		err = mock.ExpectationsWereMet()
		require.NoError(t, err)
	})

	t.Run("Пустой токен", func(t *testing.T) {
		mock, err := pgxmock.NewPool()
		require.NoError(t, err)
		defer mock.Close()

		mock.ExpectExec("UPDATE refresh_tokens").
			WithArgs("").
			WillReturnResult(pgxmock.NewResult("UPDATE", 0))

		repo := postgres.NewTokenRepository(mock)

		err = repo.RevokeToken(ctx, "")

		assert.ErrorIs(t, err, services.ErrInvalidRefreshToken)

		err = mock.ExpectationsWereMet()
		require.NoError(t, err)
	})
}
