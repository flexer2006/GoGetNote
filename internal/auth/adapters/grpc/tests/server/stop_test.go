package server_test

import (
	"context"
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	grpcServer "gogetnote/internal/auth/adapters/grpc"
	"gogetnote/internal/auth/config"
	"gogetnote/pkg/logger"
)

const (
	LogFailedToCloseListener     = "failed to close listener"
	LogFailedToCloseConnection   = "failed to close connection"
	LogServerListeningBeforeStop = "server should be listening before stopping"
	LogConnectionFailAfterStop   = "connection should fail after server is stopped"
)

func TestStop(t *testing.T) {
	t.Parallel()

	testLogger, err := logger.NewLogger(logger.Development, "debug")
	require.NoError(t, err)
	ctx := logger.NewContext(context.Background(), testLogger)

	testCases := []struct {
		name string
	}{
		{
			name: "graceful shutdown",
		},
		{
			name: "stop server without starting",
		},
	}

	for _, tcc := range testCases {
		ttcc := tcc
		t.Run(ttcc.name, func(t *testing.T) {
			t.Parallel()

			switch ttcc.name {
			case "graceful shutdown":
				listener, err := net.Listen("tcp", "localhost:0")
				require.NoError(t, err)

				port := listener.Addr().(*net.TCPAddr).Port
				address := fmt.Sprintf("localhost:%d", port)

				if err := listener.Close(); err != nil {
					t.Logf(LogFailedToCloseListener+": %v", err)
				}

				cfg := &config.GRPCConfig{
					Host: "localhost",
					Port: port,
				}
				server := grpcServer.New(cfg)
				require.NotNil(t, server)

				err = server.Start(ctx)
				require.NoError(t, err)

				time.Sleep(100 * time.Millisecond)

				conn, err := net.DialTimeout("tcp", address, 500*time.Millisecond)
				require.NoError(t, err, LogServerListeningBeforeStop)

				if err := conn.Close(); err != nil {
					t.Logf(LogFailedToCloseConnection+": %v", err)
				}

				server.Stop(ctx)

				_, err = net.DialTimeout("tcp", address, 500*time.Millisecond)
				require.Error(t, err, LogConnectionFailAfterStop)

			case "stop server without starting":
				cfg := &config.GRPCConfig{
					Host: "localhost",
					Port: 0,
				}
				server := grpcServer.New(cfg)
				require.NotNil(t, server)

				server.Stop(ctx)
			}
		})
	}
}
