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

	require.NotNil(t, repoFactory, "New repository factory should not be nil")
	assert.IsType(t, &postgres.RepositoryFactory{}, repoFactory, "Should return *postgres.RepositoryFactory")
}

func TestRepositoryFactoryUserRepository(t *testing.T) {
	mockPool := &pgxpool.Pool{}

	repoFactory := postgres.NewRepositoryFactory(mockPool)

	userRepo := repoFactory.UserRepository()

	require.NotNil(t, userRepo, "User repository should not be nil")

	_, ok := userRepo.(repositories.UserRepository)
	assert.True(t, ok, "User repository should implement repositories.UserRepository interface")
}

func TestRepositoryFactoryTokenRepository(t *testing.T) {
	mockPool := &pgxpool.Pool{}

	repoFactory := postgres.NewRepositoryFactory(mockPool)

	tokenRepo := repoFactory.TokenRepository()

	require.NotNil(t, tokenRepo, "Token repository should not be nil")

	_, ok := tokenRepo.(repositories.TokenRepository)
	assert.True(t, ok, "Token repository should implement repositories.TokenRepository interface")
}

func TestRepositoryFactoryImplementation(t *testing.T) {
	var factory interface{} = &postgres.RepositoryFactory{}

	_, hasUserRepoMethod := factory.(interface {
		UserRepository() repositories.UserRepository
	})
	_, hasTokenRepoMethod := factory.(interface {
		TokenRepository() repositories.TokenRepository
	})

	assert.True(t, hasUserRepoMethod, "Factory should have UserRepository() method")
	assert.True(t, hasTokenRepoMethod, "Factory should have TokenRepository() method")
}
