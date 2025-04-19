package tokenrepo_test

import (
	"context"
	"testing"

	"github.com/pashagolub/pgxmock/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"gogetnote/internal/auth/adapters/postgres"
	"gogetnote/internal/auth/domain/services"
	"gogetnote/pkg/logger"
)

const ErrMsgRevokingRefreshToken = "error revoking refresh token"

func TestTokenRepository_RevokeToken(t *testing.T) {
	ctx := context.Background()
	testLogger, err := logger.NewLogger(logger.Development, "debug")
	require.NoError(t, err)
	ctx = logger.NewContext(ctx, testLogger)

	const tokenValue = "test-token-value"

	t.Run("successful token cancellation", func(t *testing.T) {
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

	t.Run("the token was not found", func(t *testing.T) {
		mock, err := pgxmock.NewPool()
		require.NoError(t, err)
		defer mock.Close()

		mock.ExpectExec("UPDATE refresh_tokens").
			WithArgs(tokenValue).
			WillReturnResult(pgxmock.NewResult("UPDATE", 0))

		repo := postgres.NewTokenRepository(mock)

		err = repo.RevokeToken(ctx, tokenValue)

		require.ErrorIs(t, err, services.ErrInvalidRefreshToken)

		err = mock.ExpectationsWereMet()
		require.NoError(t, err)
	})

	t.Run("database error", func(t *testing.T) {
		mock, err := pgxmock.NewPool()
		require.NoError(t, err)
		defer mock.Close()

		mock.ExpectExec("UPDATE refresh_tokens").
			WithArgs(tokenValue).
			WillReturnError(ErrDatabaseConnection)

		repo := postgres.NewTokenRepository(mock)

		err = repo.RevokeToken(ctx, tokenValue)

		require.Error(t, err)

		assert.Contains(t, err.Error(), ErrMsgRevokingRefreshToken)

		err = mock.ExpectationsWereMet()
		require.NoError(t, err)
	})

	t.Run("an empty token", func(t *testing.T) {
		mock, err := pgxmock.NewPool()
		require.NoError(t, err)
		defer mock.Close()

		mock.ExpectExec("UPDATE refresh_tokens").
			WithArgs("").
			WillReturnResult(pgxmock.NewResult("UPDATE", 0))

		repo := postgres.NewTokenRepository(mock)

		err = repo.RevokeToken(ctx, "")

		require.ErrorIs(t, err, services.ErrInvalidRefreshToken)

		err = mock.ExpectationsWereMet()
		require.NoError(t, err)
	})
}
