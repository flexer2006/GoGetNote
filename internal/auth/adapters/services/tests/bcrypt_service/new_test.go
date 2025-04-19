package bcrypt_service_test

import (
	"context"
	"github.com/stretchr/testify/require"
	"gogetnote/internal/auth/adapters/services"
	"testing"

	"github.com/stretchr/testify/assert"
	cryptobcrypt "golang.org/x/crypto/bcrypt"

	svc "gogetnote/internal/auth/ports/services"
)

const (
	msgServiceNotNil             = "service should not be nil"
	msgImplementsPasswordService = "service should implement password service interface"
	msgNoErrorHashing            = "should not return error when hashing"
	msgNoErrorGettingCost        = "should not return error when getting cost"
	msgCostMatchesExpected       = "cost in hash should match expected value"
	msgUsesDefaultCostForLow     = "should use default cost when cost is below minimum"
)

func TestNew(t *testing.T) {
	tests := []struct {
		name     string
		cost     int
		wantCost int
	}{
		{
			name:     "valid cost value",
			cost:     10,
			wantCost: 10,
		},
		{
			name:     "minimum cost value",
			cost:     cryptobcrypt.MinCost,
			wantCost: cryptobcrypt.MinCost,
		},
		{
			name:     "cost below minimum",
			cost:     cryptobcrypt.MinCost - 1,
			wantCost: cryptobcrypt.DefaultCost,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			service := services.NewBcrypt(tt.cost)

			assert.NotNil(t, service, msgServiceNotNil)
			assert.Implements(t, (*svc.PasswordService)(nil), service, msgImplementsPasswordService)
		})
	}
}

func TestNew_UsesCorrectCost(t *testing.T) {
	cost := 10
	service := services.NewBcrypt(cost)

	password := "testPassword123"
	ctx := context.Background()
	hash, err := service.Hash(ctx, password)

	require.NoError(t, err, msgNoErrorHashing)

	hashInfo, err := cryptobcrypt.Cost([]byte(hash))
	require.NoError(t, err, msgNoErrorGettingCost)
	assert.Equal(t, cost, hashInfo, msgCostMatchesExpected)
}

func TestNew_AdjustsLowCost(t *testing.T) {
	service := services.NewBcrypt(cryptobcrypt.MinCost - 1)

	password := "testPassword123"
	ctx := context.Background()
	hash, err := service.Hash(ctx, password)

	require.NoError(t, err, msgNoErrorHashing)

	hashInfo, err := cryptobcrypt.Cost([]byte(hash))
	require.NoError(t, err, msgNoErrorGettingCost)
	assert.Equal(t, cryptobcrypt.DefaultCost, hashInfo, msgUsesDefaultCostForLow)
}
