package userrepo_test

import (
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"gogetnote/internal/auth/adapters/postgres"
	"gogetnote/internal/auth/ports/repositories"
)

func TestNewUserRepository(t *testing.T) {
	mockPool := &pgxpool.Pool{}

	tests := []struct {
		name string
		pool *pgxpool.Pool
		want repositories.UserRepository
	}{
		{
			name: "Creates repository with valid pool",
			pool: mockPool,
			want: &postgres.UserRepository{},
		},
		{
			name: "Creates repository with nil pool",
			pool: nil,
			want: &postgres.UserRepository{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			repo := postgres.NewUserRepository(tt.pool)

			require.NotNil(t, repo, "Repository should not be nil")

			_, ok := repo.(repositories.UserRepository)
			assert.True(t, ok, "Repository should implement UserRepository interface")

			assert.IsType(t, tt.want, repo, "Repository should be of type *postgres.UserRepository")

		})
	}
}

func TestUserRepositoryImplementsInterface(t *testing.T) {
	var _ repositories.UserRepository = (*postgres.UserRepository)(nil)
}
