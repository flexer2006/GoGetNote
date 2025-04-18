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

	t.Run("Успешное сохранение токена", func(t *testing.T) {
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

	t.Run("Ошибка базы данных", func(t *testing.T) {
		mock, err := pgxmock.NewPool()
		require.NoError(t, err)
		defer mock.Close()

		dbError := errors.New("database connection failed")
		mock.ExpectExec("INSERT INTO refresh_tokens").
			WithArgs(testToken.UserID, testToken.Token, testToken.ExpiresAt, testToken.IsRevoked).
			WillReturnError(dbError)

		repo := postgres.NewTokenRepository(mock)

		err = repo.StoreRefreshToken(ctx, testToken)

		assert.Error(t, err)
		assert.Contains(t, err.Error(), "error storing refresh token")

		err = mock.ExpectationsWereMet()
		require.NoError(t, err)
	})

	t.Run("Пустой ID пользователя", func(t *testing.T) {
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
			WillReturnError(errors.New("foreign key violation"))

		repo := postgres.NewTokenRepository(mock)

		err = repo.StoreRefreshToken(ctx, tokenWithEmptyUserID)

		assert.Error(t, err)
		assert.Contains(t, err.Error(), "error storing refresh token")

		err = mock.ExpectationsWereMet()
		require.NoError(t, err)
	})

	t.Run("Пустое значение токена", func(t *testing.T) {

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
			WillReturnError(errors.New("check constraint violation"))

		repo := postgres.NewTokenRepository(mock)

		err = repo.StoreRefreshToken(ctx, tokenWithEmptyValue)

		assert.Error(t, err)
		assert.Contains(t, err.Error(), "error storing refresh token")

		err = mock.ExpectationsWereMet()
		require.NoError(t, err)
	})
}
