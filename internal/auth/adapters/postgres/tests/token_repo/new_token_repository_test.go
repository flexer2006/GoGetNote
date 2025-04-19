package tokenrepo_test

import (
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"gogetnote/internal/auth/adapters/postgres"
	"gogetnote/internal/auth/ports/repositories"
)

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
