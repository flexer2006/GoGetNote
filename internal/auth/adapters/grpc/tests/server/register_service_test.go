package server_test

import (
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
	"google.golang.org/grpc"

	grpcServer "gogetnote/internal/auth/adapters/grpc"
	"gogetnote/internal/auth/config"
)

const (
	registrationFunctionCalledMsg   = "registration function should be called"
	serverPassedToRegistrationFnMsg = "server should be passed to registration function"
)

func TestRegisterService(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name string
	}{
		{
			name: "successfully register service",
		},
	}

	for _, tcc := range testCases {
		ttcc := tcc
		t.Run(ttcc.name, func(t *testing.T) {
			t.Parallel()

			cfg := &config.GRPCConfig{
				Host: "localhost",
				Port: 50051,
			}
			server := grpcServer.New(cfg)
			assert.NotNil(t, server)

			var called int32
			var passedServer *grpc.Server
			mockRegisterFn := func(srv *grpc.Server) {
				atomic.StoreInt32(&called, 1)
				passedServer = srv
			}

			server.RegisterService(mockRegisterFn)

			assert.Equal(t, int32(1), atomic.LoadInt32(&called), registrationFunctionCalledMsg)
			assert.NotNil(t, passedServer, serverPassedToRegistrationFnMsg)
		})
	}
}
