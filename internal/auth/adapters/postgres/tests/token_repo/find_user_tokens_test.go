package tokenrepo_test

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/pashagolub/pgxmock/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"gogetnote/internal/auth/adapters/postgres"
	"gogetnote/internal/auth/domain/services"
	"gogetnote/pkg/logger"
)

var (
	errDatabaseConnection = errors.New("database connection failed")
	errScanningRow        = errors.New("incompatible types")
)

const (
	errMsgQueryingUserTok  = "error querying user tokens"
	errMsgScanningTokenRow = "error scanning token row"
	errMsgScanningRow      = "error scanning row:"
)

func TestTokenRepository_FindUserTokens(t *testing.T) {
	ctx := context.Background()
	testLogger, err := logger.NewLogger(logger.Development, "debug")
	require.NoError(t, err)
	ctx = logger.NewContext(ctx, testLogger)

	const userID = "test-user-id"

	testToken1 := &services.RefreshToken{
		ID:        "test-token-id-1",
		UserID:    userID,
		Token:     "test-token-value-1",
		ExpiresAt: time.Now().UTC().Add(24 * time.Hour).Truncate(time.Microsecond),
		CreatedAt: time.Now().UTC().Truncate(time.Microsecond),
		IsRevoked: false,
	}

	testToken2 := &services.RefreshToken{
		ID:        "test-token-id-2",
		UserID:    userID,
		Token:     "test-token-value-2",
		ExpiresAt: time.Now().UTC().Add(48 * time.Hour).Truncate(time.Microsecond),
		CreatedAt: time.Now().UTC().Add(-1 * time.Hour).Truncate(time.Microsecond),
		IsRevoked: true,
	}

	t.Run("successful receipt of user tokens", func(t *testing.T) {
		mock, err := pgxmock.NewPool()
		require.NoError(t, err)
		defer mock.Close()

		rows := pgxmock.NewRows([]string{"id", "user_id", "token", "expires_at", "created_at", "is_revoked"}).
			AddRow(testToken1.ID, testToken1.UserID, testToken1.Token, testToken1.ExpiresAt, testToken1.CreatedAt, testToken1.IsRevoked).
			AddRow(testToken2.ID, testToken2.UserID, testToken2.Token, testToken2.ExpiresAt, testToken2.CreatedAt, testToken2.IsRevoked)

		mock.ExpectQuery("SELECT id, user_id, token, expires_at, created_at, is_revoked").
			WithArgs(userID).
			WillReturnRows(rows)

		repo := postgres.NewTokenRepository(mock)

		tokens, err := repo.FindUserTokens(ctx, userID)

		require.NoError(t, err)
		assert.Len(t, tokens, 2)

		assert.Equal(t, testToken1.ID, tokens[0].ID)
		assert.Equal(t, testToken1.UserID, tokens[0].UserID)
		assert.Equal(t, testToken1.Token, tokens[0].Token)
		assert.Equal(t, testToken1.ExpiresAt, tokens[0].ExpiresAt)
		assert.Equal(t, testToken1.CreatedAt, tokens[0].CreatedAt)
		assert.Equal(t, testToken1.IsRevoked, tokens[0].IsRevoked)

		assert.Equal(t, testToken2.ID, tokens[1].ID)
		assert.Equal(t, testToken2.UserID, tokens[1].UserID)
		assert.Equal(t, testToken2.Token, tokens[1].Token)
		assert.Equal(t, testToken2.ExpiresAt, tokens[1].ExpiresAt)
		assert.Equal(t, testToken2.CreatedAt, tokens[1].CreatedAt)
		assert.Equal(t, testToken2.IsRevoked, tokens[1].IsRevoked)

		err = mock.ExpectationsWereMet()
		require.NoError(t, err)
	})

	t.Run("a user without tokens", func(t *testing.T) {
		mock, err := pgxmock.NewPool()
		require.NoError(t, err)
		defer mock.Close()

		rows := pgxmock.NewRows([]string{"id", "user_id", "token", "expires_at", "created_at", "is_revoked"})

		mock.ExpectQuery("SELECT id, user_id, token, expires_at, created_at, is_revoked").
			WithArgs(userID).
			WillReturnRows(rows)

		repo := postgres.NewTokenRepository(mock)

		tokens, err := repo.FindUserTokens(ctx, userID)

		require.NoError(t, err)
		assert.Empty(t, tokens)

		err = mock.ExpectationsWereMet()
		require.NoError(t, err)
	})

	t.Run("database error", func(t *testing.T) {
		mock, err := pgxmock.NewPool()
		require.NoError(t, err)
		defer mock.Close()

		mock.ExpectQuery("SELECT id, user_id, token, expires_at, created_at, is_revoked").
			WithArgs(userID).
			WillReturnError(errDatabaseConnection)

		repo := postgres.NewTokenRepository(mock)

		tokens, err := repo.FindUserTokens(ctx, userID)

		assert.Nil(t, tokens)
		require.Error(t, err)
		assert.Contains(t, err.Error(), errMsgQueryingUserTok)

		err = mock.ExpectationsWereMet()
		require.NoError(t, err)
	})

	t.Run("error when scanning strings", func(t *testing.T) {
		mock, err := pgxmock.NewPool()
		require.NoError(t, err)
		defer mock.Close()

		scanError := fmt.Errorf("%s %w", errMsgScanningRow, errScanningRow)

		rows := pgxmock.NewRows([]string{"id", "user_id", "token", "expires_at", "created_at", "is_revoked"}).
			AddRow(testToken1.ID, testToken1.UserID, testToken1.Token, testToken1.ExpiresAt, testToken1.CreatedAt, testToken1.IsRevoked).
			RowError(0, scanError)

		mock.ExpectQuery("SELECT id, user_id, token, expires_at, created_at, is_revoked").
			WithArgs(userID).
			WillReturnRows(rows)

		repo := postgres.NewTokenRepository(mock)

		tokens, err := repo.FindUserTokens(ctx, userID)

		assert.Nil(t, tokens)
		require.Error(t, err)
		assert.Contains(t, err.Error(), errMsgScanningTokenRow)
		assert.Contains(t, err.Error(), errMsgScanningRow)

		err = mock.ExpectationsWereMet()
		require.NoError(t, err)
	})

	t.Run("empty User ID", func(t *testing.T) {
		mock, err := pgxmock.NewPool()
		require.NoError(t, err)
		defer mock.Close()

		rows := pgxmock.NewRows([]string{"id", "user_id", "token", "expires_at", "created_at", "is_revoked"})

		mock.ExpectQuery("SELECT id, user_id, token, expires_at, created_at, is_revoked").
			WithArgs("").
			WillReturnRows(rows)

		repo := postgres.NewTokenRepository(mock)

		tokens, err := repo.FindUserTokens(ctx, "")

		require.NoError(t, err)
		assert.Empty(t, tokens)

		err = mock.ExpectationsWereMet()
		require.NoError(t, err)
	})
}
