package tokenrepo_test

import (
	"context"
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

	t.Run("successful token clearing", func(t *testing.T) {
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

	t.Run("clearing without deleting tokens", func(t *testing.T) {
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

	t.Run("database error", func(t *testing.T) {
		mock, err := pgxmock.NewPool()
		require.NoError(t, err)
		defer mock.Close()

		mock.ExpectExec("DELETE FROM refresh_tokens").
			WillReturnError(ErrDatabaseConnection)

		repo := postgres.NewTokenRepository(mock)

		err = repo.CleanupExpiredTokens(ctx)

		require.Error(t, err)
		assert.Contains(t, err.Error(), "error cleaning up expired tokens")

		err = mock.ExpectationsWereMet()
		require.NoError(t, err)
	})
}
