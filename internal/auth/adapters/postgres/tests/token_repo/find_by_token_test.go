package tokenrepo_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/pashagolub/pgxmock/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"gogetnote/internal/auth/adapters/postgres"
	"gogetnote/internal/auth/domain/services"
	"gogetnote/pkg/logger"
)

func TestTokenRepository_FindByToken(t *testing.T) {
	ctx := context.Background()
	testLogger, err := logger.NewLogger(logger.Development, "debug")
	require.NoError(t, err)
	ctx = logger.NewContext(ctx, testLogger)

	testToken := &services.RefreshToken{
		ID:        "test-token-id",
		UserID:    "test-user-id",
		Token:     "test-token-value",
		ExpiresAt: time.Now().UTC().Add(24 * time.Hour).Truncate(time.Microsecond),
		CreatedAt: time.Now().UTC().Truncate(time.Microsecond),
		IsRevoked: false,
	}

	t.Run("Успешное получение токена", func(t *testing.T) {
		mock, err := pgxmock.NewPool()
		require.NoError(t, err)
		defer mock.Close()

		rows := pgxmock.NewRows([]string{"id", "user_id", "token", "expires_at", "created_at", "is_revoked"}).
			AddRow(testToken.ID, testToken.UserID, testToken.Token, testToken.ExpiresAt, testToken.CreatedAt, testToken.IsRevoked)

		mock.ExpectQuery("SELECT id, user_id, token, expires_at, created_at, is_revoked").
			WithArgs(testToken.Token).
			WillReturnRows(rows)

		repo := postgres.NewTokenRepository(mock)

		token, err := repo.FindByToken(ctx, testToken.Token)

		require.NoError(t, err)
		assert.Equal(t, testToken.ID, token.ID)
		assert.Equal(t, testToken.UserID, token.UserID)
		assert.Equal(t, testToken.Token, token.Token)
		assert.Equal(t, testToken.ExpiresAt, token.ExpiresAt)
		assert.Equal(t, testToken.CreatedAt, token.CreatedAt)
		assert.Equal(t, testToken.IsRevoked, token.IsRevoked)

		err = mock.ExpectationsWereMet()
		require.NoError(t, err)
	})

	t.Run("Токен не найден", func(t *testing.T) {
		mock, err := pgxmock.NewPool()
		require.NoError(t, err)
		defer mock.Close()

		mock.ExpectQuery("SELECT id, user_id, token, expires_at, created_at, is_revoked").
			WithArgs("non-existent-token").
			WillReturnError(pgx.ErrNoRows)

		repo := postgres.NewTokenRepository(mock)

		token, err := repo.FindByToken(ctx, "non-existent-token")

		assert.Nil(t, token)
		assert.ErrorIs(t, err, services.ErrInvalidRefreshToken)

		err = mock.ExpectationsWereMet()
		require.NoError(t, err)
	})

	t.Run("Ошибка базы данных", func(t *testing.T) {
		mock, err := pgxmock.NewPool()
		require.NoError(t, err)
		defer mock.Close()

		dbError := errors.New("database connection failed")
		mock.ExpectQuery("SELECT id, user_id, token, expires_at, created_at, is_revoked").
			WithArgs(testToken.Token).
			WillReturnError(dbError)

		repo := postgres.NewTokenRepository(mock)

		token, err := repo.FindByToken(ctx, testToken.Token)

		assert.Nil(t, token)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "error querying refresh token")

		err = mock.ExpectationsWereMet()
		require.NoError(t, err)
	})

	t.Run("Пустой токен", func(t *testing.T) {
		mock, err := pgxmock.NewPool()
		require.NoError(t, err)
		defer mock.Close()

		mock.ExpectQuery("SELECT id, user_id, token, expires_at, created_at, is_revoked").
			WithArgs("").
			WillReturnError(pgx.ErrNoRows)

		repo := postgres.NewTokenRepository(mock)

		token, err := repo.FindByToken(ctx, "")

		assert.Nil(t, token)
		assert.ErrorIs(t, err, services.ErrInvalidRefreshToken)

		err = mock.ExpectationsWereMet()
		require.NoError(t, err)
	})
}
