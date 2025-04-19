package repofactory_test

import (
	"context"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"gogetnote/internal/auth/adapters/postgres"
	"gogetnote/internal/auth/domain/services"
)

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
