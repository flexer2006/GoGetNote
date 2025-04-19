package userrepo_test

import (
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"gogetnote/internal/auth/adapters/postgres"
	"gogetnote/internal/auth/ports/repositories"
)

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
