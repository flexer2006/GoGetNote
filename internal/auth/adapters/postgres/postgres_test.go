package postgres_test

import (
	"context"
	"errors"
	"fmt"
	"gogetnote/internal/auth/adapters/postgres"
	"gogetnote/internal/auth/domain/entities"
	"gogetnote/internal/auth/domain/services"
	"gogetnote/internal/auth/ports/repositories"
	"gogetnote/pkg/logger"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/pashagolub/pgxmock/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewRepositoryFactory(t *testing.T) {
	mockPool := &pgxpool.Pool{}

	repoFactory := postgres.NewRepositoryFactory(mockPool)

	require.NotNil(t, repoFactory, "new repository factory should not be nil")
	assert.IsType(t, &postgres.RepositoryFactory{}, repoFactory, "should return *postgres.RepositoryFactory")
}

func TestRepositoryFactoryUserRepository(t *testing.T) {
	mockPool := &pgxpool.Pool{}

	repoFactory := postgres.NewRepositoryFactory(mockPool)

	userRepo := repoFactory.UserRepository()

	require.NotNil(t, userRepo, "user repository should not be nil")

	assert.Implements(t, (*repositories.UserRepository)(nil), userRepo,
		"user repository should implement repositories.UserRepository interface")
}

func TestRepositoryFactoryTokenRepository(t *testing.T) {
	mockPool := &pgxpool.Pool{}

	repoFactory := postgres.NewRepositoryFactory(mockPool)

	tokenRepo := repoFactory.TokenRepository()

	require.NotNil(t, tokenRepo, "token repository should not be nil")

	assert.Implements(t, (*repositories.TokenRepository)(nil), tokenRepo,
		"token repository should implement repositories.TokenRepository interface")
}

func TestRepositoryFactoryImplementation(t *testing.T) {
	var factory interface{} = &postgres.RepositoryFactory{}

	_, hasUserRepoMethod := factory.(interface {
		UserRepository() repositories.UserRepository
	})
	_, hasTokenRepoMethod := factory.(interface {
		TokenRepository() repositories.TokenRepository
	})

	assert.True(t, hasUserRepoMethod, "factory should have UserRepository() method")
	assert.True(t, hasTokenRepoMethod, "factory should have TokenRepository() method")
}

func TestRepositoryFactory_TokenRepository(t *testing.T) {
	mockPool := &pgxpool.Pool{}

	repoFactory := postgres.NewRepositoryFactory(mockPool)
	require.NotNil(t, repoFactory, "Repository factory should not be nil")

	tokenRepo := repoFactory.TokenRepository()

	require.NotNil(t, tokenRepo, "Token repository should not be nil")

	tokenRepo2 := repoFactory.TokenRepository()
	assert.Same(t, tokenRepo, tokenRepo2, "Multiple calls should return the same repository instance")

	_, ok := tokenRepo.(*postgres.TokenRepository)
	assert.True(t, ok, "Token repository should be of type *postgres.TokenRepository")

	t.Run("Interface implementation check", func(_ *testing.T) {
		var _ interface {
			StoreRefreshToken(ctx context.Context, token *services.RefreshToken) error
			FindByToken(ctx context.Context, token string) (*services.RefreshToken, error)
			RevokeToken(ctx context.Context, token string) error
			RevokeAllUserTokens(ctx context.Context, userID string) error
			CleanupExpiredTokens(ctx context.Context) error
			FindUserTokens(ctx context.Context, userID string) ([]*services.RefreshToken, error)
		} = tokenRepo
	})
}

func TestRepositoryFactory_UserRepository(t *testing.T) {
	mockPool := &pgxpool.Pool{}

	repoFactory := postgres.NewRepositoryFactory(mockPool)
	require.NotNil(t, repoFactory, "repository factory should not be nil")

	userRepo := repoFactory.UserRepository()

	require.NotNil(t, userRepo, "user repository should not be nil")

	userRepo2 := repoFactory.UserRepository()
	assert.Same(t, userRepo, userRepo2, "multiple calls should return the same repository instance")

	_, ok := userRepo.(*postgres.UserRepository)
	assert.True(t, ok, "user repository should be of type *postgres.UserRepository")

	t.Run("interface implementation check", func(_ *testing.T) {
		var _ interface {
			FindByID(ctx context.Context, id string) (*entities.User, error)
			FindByEmail(ctx context.Context, email string) (*entities.User, error)
			Create(ctx context.Context, user *entities.User) (*entities.User, error)
			Update(ctx context.Context, user *entities.User) (*entities.User, error)
			Delete(ctx context.Context, id string) error
		} = userRepo
	})
}

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

const (
	errRepositoryNil  = "repository should not be nil"
	errRepositoryType = "repository should be of type *postgres.TokenRepository"
)

func TestNewTokenRepository(t *testing.T) {
	mockPool := &pgxpool.Pool{}

	tests := []struct {
		name string
		pool *pgxpool.Pool
		want repositories.TokenRepository
	}{
		{
			name: "creates repository with valid pool",
			pool: mockPool,
			want: &postgres.TokenRepository{},
		},
		{
			name: "creates repository with nil pool",
			pool: nil,
			want: &postgres.TokenRepository{},
		},
	}

	for _, ttt := range tests {
		t.Run(ttt.name, func(t *testing.T) {
			repo := postgres.NewTokenRepository(ttt.pool)

			require.NotNil(t, repo, errRepositoryNil)

			assert.IsType(t, ttt.want, repo, errRepositoryType)
		})
	}
}

func TestTokenRepositoryImplementsInterface(_ *testing.T) {
	var _ repositories.TokenRepository = (*postgres.TokenRepository)(nil)
}

const (
	errRevokingAllUserTokens = "error revoking all user tokens"
)

func TestTokenRepository_RevokeAllUserTokens(t *testing.T) {
	ctx := context.Background()
	testLogger, err := logger.NewLogger(logger.Development, "debug")
	require.NoError(t, err)
	ctx = logger.NewContext(ctx, testLogger)

	const userID = "test-user-id"

	t.Run("successful cancellation of all user tokens", func(t *testing.T) {
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

	t.Run("token cancellation - there are no active tokens", func(t *testing.T) {
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

	t.Run("database error", func(t *testing.T) {
		mock, err := pgxmock.NewPool()
		require.NoError(t, err)
		defer mock.Close()

		mock.ExpectExec("UPDATE refresh_tokens").
			WithArgs(userID).
			WillReturnError(ErrDatabaseConnection)

		repo := postgres.NewTokenRepository(mock)

		err = repo.RevokeAllUserTokens(ctx, userID)

		require.Error(t, err)
		assert.Contains(t, err.Error(), errRevokingAllUserTokens)

		err = mock.ExpectationsWereMet()
		require.NoError(t, err)
	})

	t.Run("empty User ID", func(t *testing.T) {
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

var (
	errDuplicateKey = errors.New("duplicate key value violates unique constraint")
)

const ErrCreatingUser = "error creating user"

func assertUserEquals(t *testing.T, expected, actual *entities.User) {
	t.Helper()
	require.NotNil(t, actual)
	assert.Equal(t, expected.ID, actual.ID)
	assert.Equal(t, expected.Email, actual.Email)
	assert.Equal(t, expected.Username, actual.Username)
	assert.Equal(t, expected.PasswordHash, actual.PasswordHash)
	assert.Equal(t, expected.CreatedAt, actual.CreatedAt)
	assert.Equal(t, expected.UpdatedAt, actual.UpdatedAt)
}

func TestUserRepository_Create(t *testing.T) {
	ctx := context.Background()
	testLogger, err := logger.NewLogger(logger.Development, "debug")
	require.NoError(t, err)
	ctx = logger.NewContext(ctx, testLogger)

	inputUser := &entities.User{
		Email:        "new@example.com",
		Username:     "newuser",
		PasswordHash: "hashed_new_password",
	}

	expectedUser := entities.User{
		ID:           "generated-uuid",
		Email:        inputUser.Email,
		Username:     inputUser.Username,
		PasswordHash: inputUser.PasswordHash,
		CreatedAt:    time.Now().UTC().Truncate(time.Microsecond),
		UpdatedAt:    time.Now().UTC().Truncate(time.Microsecond),
	}

	t.Run("successful user creation", func(t *testing.T) {
		mock, err := pgxmock.NewPool()
		require.NoError(t, err)
		defer mock.Close()

		mock.ExpectQuery("INSERT INTO users .+").
			WithArgs(inputUser.Email, inputUser.Username, inputUser.PasswordHash).
			WillReturnRows(
				pgxmock.NewRows([]string{"id", "email", "username", "password_hash", "created_at", "updated_at"}).
					AddRow(expectedUser.ID, expectedUser.Email, expectedUser.Username, expectedUser.PasswordHash, expectedUser.CreatedAt, expectedUser.UpdatedAt),
			)

		repo := postgres.NewUserRepository(mock)
		createdUser, err := repo.Create(ctx, inputUser)

		require.NoError(t, err)
		assertUserEquals(t, &expectedUser, createdUser)

		err = mock.ExpectationsWereMet()
		require.NoError(t, err)
	})

	t.Run("error when creating a user is a common database error", func(t *testing.T) {
		mock, err := pgxmock.NewPool()
		require.NoError(t, err)
		defer mock.Close()

		mock.ExpectQuery("INSERT INTO users .+").
			WithArgs(inputUser.Email, inputUser.Username, inputUser.PasswordHash).
			WillReturnError(errDatabaseConnection)

		repo := postgres.NewUserRepository(mock)
		createdUser, err := repo.Create(ctx, inputUser)

		require.Nil(t, createdUser)
		require.Error(t, err)
		require.Contains(t, err.Error(), ErrCreatingUser)

		err = mock.ExpectationsWereMet()
		require.NoError(t, err)
	})

	t.Run("error when creating a user - duplicate email", func(t *testing.T) {
		mock, err := pgxmock.NewPool()
		require.NoError(t, err)
		defer mock.Close()

		mock.ExpectQuery("INSERT INTO users .+").
			WithArgs(inputUser.Email, inputUser.Username, inputUser.PasswordHash).
			WillReturnError(errDuplicateKey)

		repo := postgres.NewUserRepository(mock)
		createdUser, err := repo.Create(ctx, inputUser)

		require.Nil(t, createdUser)
		require.Error(t, err)
		require.Contains(t, err.Error(), ErrCreatingUser)

		err = mock.ExpectationsWereMet()
		require.NoError(t, err)
	})

	t.Run("creating a user with minimal data", func(t *testing.T) {
		mock, err := pgxmock.NewPool()
		require.NoError(t, err)
		defer mock.Close()

		minimalUser := &entities.User{
			Email:        "minimal@example.com",
			Username:     "minimal",
			PasswordHash: "hash",
		}

		expectedMinimalUser := entities.User{
			ID:           "generated-minimal-uuid",
			Email:        minimalUser.Email,
			Username:     minimalUser.Username,
			PasswordHash: minimalUser.PasswordHash,
			CreatedAt:    time.Now().UTC().Truncate(time.Microsecond),
			UpdatedAt:    time.Now().UTC().Truncate(time.Microsecond),
		}

		mock.ExpectQuery("INSERT INTO users .+").
			WithArgs(minimalUser.Email, minimalUser.Username, minimalUser.PasswordHash).
			WillReturnRows(
				pgxmock.NewRows([]string{"id", "email", "username", "password_hash", "created_at", "updated_at"}).
					AddRow(expectedMinimalUser.ID, expectedMinimalUser.Email, expectedMinimalUser.Username,
						expectedMinimalUser.PasswordHash, expectedMinimalUser.CreatedAt, expectedMinimalUser.UpdatedAt),
			)

		repo := postgres.NewUserRepository(mock)
		createdUser, err := repo.Create(ctx, minimalUser)

		require.NoError(t, err)
		assertUserEquals(t, &expectedMinimalUser, createdUser)

		err = mock.ExpectationsWereMet()
		require.NoError(t, err)
	})
}

const ErrDelUser = "error deleting user"

func TestUserRepository_Delete(t *testing.T) {
	ctx := context.Background()
	testLogger, err := logger.NewLogger(logger.Development, "debug")
	require.NoError(t, err)
	ctx = logger.NewContext(ctx, testLogger)

	const userID = "test-user-id"

	t.Run("successful user deletion", func(t *testing.T) {
		mock, err := pgxmock.NewPool()
		require.NoError(t, err)
		defer mock.Close()

		mock.ExpectExec("DELETE FROM users").
			WithArgs(userID).
			WillReturnResult(pgxmock.NewResult("DELETE", 1))

		repo := postgres.NewUserRepository(mock)

		err = repo.Delete(ctx, userID)

		require.NoError(t, err)

		err = mock.ExpectationsWereMet()
		require.NoError(t, err)
	})

	t.Run("the user was not found", func(t *testing.T) {
		mock, err := pgxmock.NewPool()
		require.NoError(t, err)
		defer mock.Close()

		mock.ExpectExec("DELETE FROM users").
			WithArgs(userID).
			WillReturnResult(pgxmock.NewResult("DELETE", 0))

		repo := postgres.NewUserRepository(mock)

		err = repo.Delete(ctx, userID)

		require.ErrorIs(t, err, entities.ErrUserNotFound)

		err = mock.ExpectationsWereMet()
		require.NoError(t, err)
	})

	t.Run("database error", func(t *testing.T) {
		mock, err := pgxmock.NewPool()
		require.NoError(t, err)
		defer mock.Close()

		mock.ExpectExec("DELETE FROM users").
			WithArgs(userID).
			WillReturnError(errDatabaseConnection)

		repo := postgres.NewUserRepository(mock)

		err = repo.Delete(ctx, userID)

		require.Error(t, err)
		require.Contains(t, err.Error(), ErrDelUser)

		err = mock.ExpectationsWereMet()
		require.NoError(t, err)
	})

	t.Run("empty User ID", func(t *testing.T) {
		mock, err := pgxmock.NewPool()
		require.NoError(t, err)
		defer mock.Close()

		mock.ExpectExec("DELETE FROM users").
			WithArgs("").
			WillReturnResult(pgxmock.NewResult("DELETE", 0))

		repo := postgres.NewUserRepository(mock)

		err = repo.Delete(ctx, "")

		require.ErrorIs(t, err, entities.ErrUserNotFound)

		err = mock.ExpectationsWereMet()
		require.NoError(t, err)
	})
}

const ErrQueryingUserByEmail = "error querying user by email"

func TestUserRepository_FindByEmail(t *testing.T) {
	ctx := context.Background()
	testLogger, err := logger.NewLogger(logger.Development, "debug")
	require.NoError(t, err)
	ctx = logger.NewContext(ctx, testLogger)

	testUser := entities.User{
		ID:           "test-user-id",
		Email:        "test@example.com",
		Username:     "testuser",
		PasswordHash: "hashed_password",
		CreatedAt:    time.Now().UTC().Truncate(time.Microsecond),
		UpdatedAt:    time.Now().UTC().Truncate(time.Microsecond),
	}

	t.Run("successful receipt of the user by email", func(t *testing.T) {
		mock, err := pgxmock.NewPool()
		require.NoError(t, err)
		defer mock.Close()

		setupUserMock(mock, testUser.Email, testUser)

		repo := postgres.NewUserRepository(mock)

		user, err := repo.FindByEmail(ctx, testUser.Email)

		require.NoError(t, err)

		assertUserEquals(t, &testUser, user)

		err = mock.ExpectationsWereMet()
		require.NoError(t, err)
	})

	t.Run("the user was not found by email", func(t *testing.T) {
		mock, err := pgxmock.NewPool()
		require.NoError(t, err)
		defer mock.Close()

		nonExistingEmail := "nonexistent@example.com"
		mock.ExpectQuery("SELECT id, email, username, password_hash, created_at, updated_at").
			WithArgs(nonExistingEmail).
			WillReturnError(pgx.ErrNoRows)

		repo := postgres.NewUserRepository(mock)

		user, err := repo.FindByEmail(ctx, nonExistingEmail)

		require.Nil(t, user)
		require.ErrorIs(t, err, entities.ErrUserNotFound)

		err = mock.ExpectationsWereMet()
		require.NoError(t, err)
	})

	t.Run("database error when searching by email", func(t *testing.T) {
		mock, err := pgxmock.NewPool()
		require.NoError(t, err)
		defer mock.Close()

		mock.ExpectQuery("SELECT id, email, username, password_hash, created_at, updated_at").
			WithArgs(testUser.Email).
			WillReturnError(ErrDatabaseConnection)

		repo := postgres.NewUserRepository(mock)

		user, err := repo.FindByEmail(ctx, testUser.Email)

		require.Nil(t, user)
		require.Error(t, err)
		require.Contains(t, err.Error(), ErrQueryingUserByEmail)

		err = mock.ExpectationsWereMet()
		require.NoError(t, err)
	})

	t.Run("empty email", func(t *testing.T) {
		mock, err := pgxmock.NewPool()
		require.NoError(t, err)
		defer mock.Close()

		mock.ExpectQuery("SELECT id, email, username, password_hash, created_at, updated_at").
			WithArgs("").
			WillReturnError(pgx.ErrNoRows)

		repo := postgres.NewUserRepository(mock)

		user, err := repo.FindByEmail(ctx, "")

		require.Nil(t, user)
		require.ErrorIs(t, err, entities.ErrUserNotFound)

		err = mock.ExpectationsWereMet()
		require.NoError(t, err)
	})
}

const ErrQueryingUserByID = "error querying user by id"

func setupUserMock(mock pgxmock.PgxPoolIface, param any, testUser entities.User) {
	rows := pgxmock.NewRows([]string{"id", "email", "username", "password_hash", "created_at", "updated_at"}).
		AddRow(testUser.ID, testUser.Email, testUser.Username, testUser.PasswordHash, testUser.CreatedAt, testUser.UpdatedAt)

	mock.ExpectQuery("SELECT id, email, username, password_hash, created_at, updated_at").
		WithArgs(param).
		WillReturnRows(rows)
}

func TestUserRepository_FindByID(t *testing.T) {
	ctx := context.Background()
	testLogger, err := logger.NewLogger(logger.Development, "debug")
	require.NoError(t, err)
	ctx = logger.NewContext(ctx, testLogger)

	testUser := entities.User{
		ID:           "test-user-id",
		Email:        "test@example.com",
		Username:     "testuser",
		PasswordHash: "hashed_password",
		CreatedAt:    time.Now().UTC().Truncate(time.Microsecond),
		UpdatedAt:    time.Now().UTC().Truncate(time.Microsecond),
	}

	t.Run("successful user acquisition", func(t *testing.T) {
		mock, err := pgxmock.NewPool()
		require.NoError(t, err)
		defer mock.Close()

		setupUserMock(mock, testUser.ID, testUser)

		repo := postgres.NewUserRepository(mock)

		user, err := repo.FindByID(ctx, testUser.ID)

		require.NoError(t, err)

		assertUserEquals(t, &testUser, user)

		err = mock.ExpectationsWereMet()
		require.NoError(t, err)
	})

	t.Run("the user was not found", func(t *testing.T) {
		mock, err := pgxmock.NewPool()
		require.NoError(t, err)
		defer mock.Close()

		mock.ExpectQuery("SELECT id, email, username, password_hash, created_at, updated_at").
			WithArgs("non-existing-id").
			WillReturnError(pgx.ErrNoRows)

		repo := postgres.NewUserRepository(mock)

		user, err := repo.FindByID(ctx, "non-existing-id")

		require.Nil(t, user)
		require.ErrorIs(t, err, entities.ErrUserNotFound)

		err = mock.ExpectationsWereMet()
		require.NoError(t, err)
	})

	t.Run("database error", func(t *testing.T) {
		mock, err := pgxmock.NewPool()
		require.NoError(t, err)
		defer mock.Close()

		mock.ExpectQuery("SELECT id, email, username, password_hash, created_at, updated_at").
			WithArgs(testUser.ID).
			WillReturnError(errDatabaseConnection)

		repo := postgres.NewUserRepository(mock)

		user, err := repo.FindByID(ctx, testUser.ID)

		assert.Nil(t, user)
		require.Error(t, err)
		assert.Contains(t, err.Error(), ErrQueryingUserByID)

		err = mock.ExpectationsWereMet()
		require.NoError(t, err)
	})

	t.Run("empty email", func(t *testing.T) {
		mock, err := pgxmock.NewPool()
		require.NoError(t, err)
		defer mock.Close()

		mock.ExpectQuery("SELECT id, email, username, password_hash, created_at, updated_at").
			WithArgs("").
			WillReturnError(pgx.ErrNoRows)

		repo := postgres.NewUserRepository(mock)

		user, err := repo.FindByID(ctx, "")

		require.Nil(t, user)
		require.ErrorIs(t, err, entities.ErrUserNotFound)

		err = mock.ExpectationsWereMet()
		require.NoError(t, err)
	})
}

const (
	errRepositoryShouldNotBeNil = "repository should not be nil"
	errRepositoryShouldBeOfType = "repository should be of type *postgres.UserRepository"
)

func TestNewUserRepository(t *testing.T) {
	mockPool := &pgxpool.Pool{}

	tests := []struct {
		name string
		pool *pgxpool.Pool
		want repositories.UserRepository
	}{
		{
			name: "creates repository with valid pool",
			pool: mockPool,
			want: &postgres.UserRepository{},
		},
		{
			name: "creates repository with nil pool",
			pool: nil,
			want: &postgres.UserRepository{},
		},
	}

	for _, ttt := range tests {
		t.Run(ttt.name, func(t *testing.T) {
			repo := postgres.NewUserRepository(ttt.pool)

			require.NotNil(t, repo, errRepositoryShouldNotBeNil)

			assert.IsType(t, ttt.want, repo, errRepositoryShouldBeOfType)
		})
	}
}

func TestUserRepositoryImplementsInterface(_ *testing.T) {
	var _ repositories.UserRepository = (*postgres.UserRepository)(nil)
}

const ErrUpdatingUser = "error updating user"

func TestUserRepository_Update(t *testing.T) {
	ctx := context.Background()
	testLogger, err := logger.NewLogger(logger.Development, "debug")
	require.NoError(t, err)
	ctx = logger.NewContext(ctx, testLogger)

	user := &entities.User{
		ID:           "existing-user-id",
		Email:        "updated@example.com",
		Username:     "updateduser",
		PasswordHash: "updated_password_hash",
	}

	expectedUser := entities.User{
		ID:           user.ID,
		Email:        user.Email,
		Username:     user.Username,
		PasswordHash: user.PasswordHash,
		CreatedAt:    time.Now().UTC().Truncate(time.Microsecond),
		UpdatedAt:    time.Now().UTC().Add(time.Second).Truncate(time.Microsecond),
	}

	t.Run("Successful user update", func(t *testing.T) {
		mock, err := pgxmock.NewPool()
		require.NoError(t, err)
		defer mock.Close()

		mock.ExpectQuery("UPDATE users SET email = \\$2, username = \\$3, password_hash = \\$4, updated_at = \\$5 WHERE id = \\$1").
			WithArgs(user.ID, user.Email, user.Username, user.PasswordHash, pgxmock.AnyArg()).
			WillReturnRows(
				pgxmock.NewRows([]string{"id", "email", "username", "password_hash", "created_at", "updated_at"}).
					AddRow(expectedUser.ID, expectedUser.Email, expectedUser.Username, expectedUser.PasswordHash, expectedUser.CreatedAt, expectedUser.UpdatedAt),
			)

		repo := postgres.NewUserRepository(mock)
		updatedUser, err := repo.Update(ctx, user)

		require.NoError(t, err)
		assertUserEquals(t, &expectedUser, updatedUser)

		err = mock.ExpectationsWereMet()
		require.NoError(t, err)
	})

	t.Run("The user was not found", func(t *testing.T) {
		mock, err := pgxmock.NewPool()
		require.NoError(t, err)
		defer mock.Close()

		mock.ExpectQuery("UPDATE users").
			WithArgs(user.ID, user.Email, user.Username, user.PasswordHash, pgxmock.AnyArg()).
			WillReturnError(pgx.ErrNoRows)

		repo := postgres.NewUserRepository(mock)
		updatedUser, err := repo.Update(ctx, user)

		require.ErrorIs(t, err, entities.ErrUserNotFound)
		require.Nil(t, updatedUser)

		err = mock.ExpectationsWereMet()
		require.NoError(t, err)
	})

	t.Run("Database error", func(t *testing.T) {
		mock, err := pgxmock.NewPool()
		require.NoError(t, err)
		defer mock.Close()

		mock.ExpectQuery("UPDATE users").
			WithArgs(user.ID, user.Email, user.Username, user.PasswordHash, pgxmock.AnyArg()).
			WillReturnError(ErrDatabaseConnection)

		repo := postgres.NewUserRepository(mock)
		updatedUser, err := repo.Update(ctx, user)

		require.Nil(t, updatedUser)
		require.Error(t, err)
		require.Contains(t, err.Error(), ErrUpdatingUser)

		err = mock.ExpectationsWereMet()
		require.NoError(t, err)
	})

	t.Run("Empty User ID", func(t *testing.T) {
		mock, err := pgxmock.NewPool()
		require.NoError(t, err)
		defer mock.Close()

		userWithEmptyID := &entities.User{
			ID:           "",
			Email:        "updated@example.com",
			Username:     "updateduser",
			PasswordHash: "updated_password_hash",
		}

		mock.ExpectQuery("UPDATE users").
			WithArgs(userWithEmptyID.ID, userWithEmptyID.Email, userWithEmptyID.Username, userWithEmptyID.PasswordHash, pgxmock.AnyArg()).
			WillReturnError(pgx.ErrNoRows)

		repo := postgres.NewUserRepository(mock)
		updatedUser, err := repo.Update(ctx, userWithEmptyID)

		require.ErrorIs(t, err, entities.ErrUserNotFound)
		require.Nil(t, updatedUser)

		err = mock.ExpectationsWereMet()
		require.NoError(t, err)
	})
}
