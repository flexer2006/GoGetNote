package repofactory_test

import (
	"context"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"gogetnote/internal/auth/adapters/postgres"
	"gogetnote/internal/auth/domain/entities"
)

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
