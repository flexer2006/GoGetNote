package tokenrepo_test

import (
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"gogetnote/internal/auth/adapters/postgres"
	"gogetnote/internal/auth/ports/repositories"
)

func TestNewTokenRepository(t *testing.T) {
	mockPool := &pgxpool.Pool{}

	tests := []struct {
		name string
		pool *pgxpool.Pool
		want repositories.TokenRepository
	}{
		{
			name: "Creates repository with valid pool",
			pool: mockPool,
			want: &postgres.TokenRepository{},
		},
		{
			name: "Creates repository with nil pool",
			pool: nil,
			want: &postgres.TokenRepository{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			repo := postgres.NewTokenRepository(tt.pool)

			require.NotNil(t, repo, "Repository should not be nil")

			_, ok := repo.(repositories.TokenRepository)
			assert.True(t, ok, "Repository should implement TokenRepository interface")

			assert.IsType(t, tt.want, repo, "Repository should be of type *postgres.TokenRepository")
		})
	}
}

func TestTokenRepositoryImplementsInterface(t *testing.T) {
	var _ repositories.TokenRepository = (*postgres.TokenRepository)(nil)
}
