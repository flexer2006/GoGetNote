package repofactory_test

import (
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"gogetnote/internal/auth/adapters/postgres"
	"gogetnote/internal/auth/ports/repositories"
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
