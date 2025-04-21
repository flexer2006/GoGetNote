package server_test

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"gogetnote/internal/auth/adapters/grpc"
	"gogetnote/internal/auth/config"
	"gogetnote/pkg/logger"
)

func TestStart(t *testing.T) {
	t.Parallel()

	testLogger, err := logger.NewLogger(logger.Development, "debug")
	require.NoError(t, err)
	ctx := logger.NewContext(context.Background(), testLogger)

	testCases := []struct {
		name        string
		cfg         *config.GRPCConfig
		expectError bool
	}{
		{
			name: "successful server start",
			cfg: &config.GRPCConfig{
				Host: "localhost",
				Port: 0,
			},
			expectError: false,
		},
		{
			name: "address already in use",
			cfg: func() *config.GRPCConfig {
				listener, err := net.Listen("tcp", "localhost:0")
				require.NoError(t, err)

				port := listener.Addr().(*net.TCPAddr).Port

				t.Cleanup(func() {
					if err := listener.Close(); err != nil {
						t.Logf(LogFailedToCloseListener+": %v", err)
					}
				})

				return &config.GRPCConfig{
					Host: "localhost",
					Port: port,
				}
			}(),
			expectError: true,
		},
		{
			name: "invalid host",
			cfg: &config.GRPCConfig{
				Host: "invalid-hostname-that-cannot-resolve",
				Port: 50051,
			},
			expectError: true,
		},
		{
			name: "permissions issue",
			cfg: &config.GRPCConfig{
				Host: "localhost",
				Port: 80,
			},
			expectError: true,
		},
		{
			name: "invalid port",
			cfg: &config.GRPCConfig{
				Host: "localhost",
				Port: -1,
			},
			expectError: true,
		},
		{
			name: "retry listener closes",
			cfg: func() *config.GRPCConfig {
				listener, err := net.Listen("tcp", "localhost:0")
				require.NoError(t, err)

				port := listener.Addr().(*net.TCPAddr).Port

				t.Cleanup(func() {
					err := listener.Close()
					if err != nil {
						t.Logf(LogFailedToCloseListener+": %v", err)
					}
				})

				return &config.GRPCConfig{
					Host: "localhost",
					Port: port,
				}
			}(),
			expectError: true,
		},
	}

	for _, tcc := range testCases {
		ttcc := tcc
		t.Run(ttcc.name, func(t *testing.T) {
			t.Parallel()

			server := grpc.New(ttcc.cfg)
			require.NotNil(t, server)

			err := server.Start(ctx)

			if ttcc.expectError {
				require.Error(t, err)
			} else {
				require.NoError(t, err)

				time.Sleep(100 * time.Millisecond)

				server.Stop(ctx)
			}
		})
	}
}
