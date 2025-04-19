package tokenrepo_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/pashagolub/pgxmock/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"gogetnote/internal/auth/adapters/postgres"
	"gogetnote/internal/auth/domain/services"
	"gogetnote/pkg/logger"
)

const ErrMsgStoringRefreshTok = "error storing refresh token"

var (
	ErrDatabaseConnection       = errors.New("database connection failed")
	ErrForeignKeyViolation      = errors.New("foreign key violation")
	ErrCheckConstraintViolation = errors.New("check constraint violation")
)

func TestTokenRepository_StoreRefreshToken(t *testing.T) {
	ctx := context.Background()
	testLogger, err := logger.NewLogger(logger.Development, "debug")
	require.NoError(t, err)
	ctx = logger.NewContext(ctx, testLogger)

	testToken := &services.RefreshToken{
		UserID:    "test-user-id",
		Token:     "test-token-value",
		ExpiresAt: time.Now().UTC().Add(24 * time.Hour).Truncate(time.Microsecond),
		IsRevoked: false,
	}

	t.Run("successful token saving", func(t *testing.T) {
		mock, err := pgxmock.NewPool()
		require.NoError(t, err)
		defer mock.Close()

		mock.ExpectExec("INSERT INTO refresh_tokens").
			WithArgs(testToken.UserID, testToken.Token, testToken.ExpiresAt, testToken.IsRevoked).
			WillReturnResult(pgxmock.NewResult("INSERT", 1))

		repo := postgres.NewTokenRepository(mock)

		err = repo.StoreRefreshToken(ctx, testToken)

		require.NoError(t, err)

		err = mock.ExpectationsWereMet()
		require.NoError(t, err)
	})

	t.Run("database error", func(t *testing.T) {
		mock, err := pgxmock.NewPool()
		require.NoError(t, err)
		defer mock.Close()

		mock.ExpectExec("INSERT INTO refresh_tokens").
			WithArgs(testToken.UserID, testToken.Token, testToken.ExpiresAt, testToken.IsRevoked).
			WillReturnError(ErrDatabaseConnection)

		repo := postgres.NewTokenRepository(mock)

		err = repo.StoreRefreshToken(ctx, testToken)

		require.Error(t, err)
		assert.Contains(t, err.Error(), ErrMsgStoringRefreshTok)

		err = mock.ExpectationsWereMet()
		require.NoError(t, err)
	})

	t.Run("empty User ID", func(t *testing.T) {
		mock, err := pgxmock.NewPool()
		require.NoError(t, err)
		defer mock.Close()

		tokenWithEmptyUserID := &services.RefreshToken{
			UserID:    "",
			Token:     "test-token-value",
			ExpiresAt: time.Now().UTC().Add(24 * time.Hour),
			IsRevoked: false,
		}

		mock.ExpectExec("INSERT INTO refresh_tokens").
			WithArgs(tokenWithEmptyUserID.UserID, tokenWithEmptyUserID.Token, tokenWithEmptyUserID.ExpiresAt, tokenWithEmptyUserID.IsRevoked).
			WillReturnError(ErrForeignKeyViolation)

		repo := postgres.NewTokenRepository(mock)

		err = repo.StoreRefreshToken(ctx, tokenWithEmptyUserID)

		require.Error(t, err)
		assert.Contains(t, err.Error(), ErrMsgStoringRefreshTok)

		err = mock.ExpectationsWereMet()
		require.NoError(t, err)
	})

	t.Run("empty token value", func(t *testing.T) {
		mock, err := pgxmock.NewPool()
		require.NoError(t, err)
		defer mock.Close()

		tokenWithEmptyValue := &services.RefreshToken{
			UserID:    "test-user-id",
			Token:     "",
			ExpiresAt: time.Now().UTC().Add(24 * time.Hour),
			IsRevoked: false,
		}

		mock.ExpectExec("INSERT INTO refresh_tokens").
			WithArgs(tokenWithEmptyValue.UserID, tokenWithEmptyValue.Token, tokenWithEmptyValue.ExpiresAt, tokenWithEmptyValue.IsRevoked).
			WillReturnError(ErrCheckConstraintViolation)

		repo := postgres.NewTokenRepository(mock)

		err = repo.StoreRefreshToken(ctx, tokenWithEmptyValue)

		require.Error(t, err)
		assert.Contains(t, err.Error(), ErrMsgStoringRefreshTok)

		err = mock.ExpectationsWereMet()
		require.NoError(t, err)
	})
}
