package tokenrepo_test

import (
	"context"
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

const (
	NonExistentToken        = "non-existent-token"
	ErrorQueryingRefreshMsg = "error querying refresh token"
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

	t.Run("successful receipt of the token", func(t *testing.T) {
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

	t.Run("the token was not found", func(t *testing.T) {
		mock, err := pgxmock.NewPool()
		require.NoError(t, err)
		defer mock.Close()

		mock.ExpectQuery("SELECT id, user_id, token, expires_at, created_at, is_revoked").
			WithArgs(NonExistentToken).
			WillReturnError(pgx.ErrNoRows)

		repo := postgres.NewTokenRepository(mock)

		token, err := repo.FindByToken(ctx, NonExistentToken)

		assert.Nil(t, token)
		require.ErrorIs(t, err, services.ErrInvalidRefreshToken)

		err = mock.ExpectationsWereMet()
		require.NoError(t, err)
	})

	t.Run("database error", func(t *testing.T) {
		mock, err := pgxmock.NewPool()
		require.NoError(t, err)
		defer mock.Close()

		mock.ExpectQuery("SELECT id, user_id, token, expires_at, created_at, is_revoked").
			WithArgs(testToken.Token).
			WillReturnError(ErrDatabaseConnection)

		repo := postgres.NewTokenRepository(mock)

		token, err := repo.FindByToken(ctx, testToken.Token)

		assert.Nil(t, token)
		require.Error(t, err)
		assert.Contains(t, err.Error(), ErrorQueryingRefreshMsg)

		err = mock.ExpectationsWereMet()
		require.NoError(t, err)
	})

	t.Run("an empty token", func(t *testing.T) {
		mock, err := pgxmock.NewPool()
		require.NoError(t, err)
		defer mock.Close()

		mock.ExpectQuery("SELECT id, user_id, token, expires_at, created_at, is_revoked").
			WithArgs("").
			WillReturnError(pgx.ErrNoRows)

		repo := postgres.NewTokenRepository(mock)

		token, err := repo.FindByToken(ctx, "")

		assert.Nil(t, token)
		require.ErrorIs(t, err, services.ErrInvalidRefreshToken)

		err = mock.ExpectationsWereMet()
		require.NoError(t, err)
	})
}
