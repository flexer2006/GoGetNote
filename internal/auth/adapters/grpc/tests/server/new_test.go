package server_test

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"gogetnote/internal/auth/adapters/grpc"
	"gogetnote/internal/auth/config"
)

func TestNew(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name      string
		cfg       *config.GRPCConfig
		expectNil bool
	}{
		{
			name: "successful server creation",
			cfg: &config.GRPCConfig{
				Host: "localhost",
				Port: 50051,
			},
			expectNil: false,
		},
		{
			name:      "creation with nil config",
			cfg:       nil,
			expectNil: false,
		},
	}

	for _, tcc := range testCases {
		ttcc := tcc
		t.Run(ttcc.name, func(t *testing.T) {
			t.Parallel()

			server := grpc.New(ttcc.cfg)

			if ttcc.expectNil {
				assert.Nil(t, server)
			} else {
				assert.NotNil(t, server)
			}
		})
	}
}
