package authhandler_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"google.golang.org/grpc"
	"google.golang.org/grpc/reflection"

	grpcAdapter "gogetnote/internal/auth/adapters/grpc"
	authv1 "gogetnote/pkg/api/auth/v1"
)

const (
	RegServiceShouldNPanicWithRealServerMsg = "RegisterService should not panic with a real gRPC server"
	AuthServiceRegisteredMsg                = "AuthService should be registered with the server"
)

type MockGRPCServer struct {
	mock.Mock
}

func (m *MockGRPCServer) RegisterService(desc *grpc.ServiceDesc, impl interface{}) {
	m.Called(desc, impl)
}

func TestRegisterService(t *testing.T) {
	t.Run("should register auth service with grpc server", func(t *testing.T) {
		mockAuthUseCase := new(MockAuthUseCase)
		handler := grpcAdapter.NewAuthHandler(mockAuthUseCase)
		mockServer := new(MockGRPCServer)

		mockServer.On("RegisterService", mock.MatchedBy(func(desc *grpc.ServiceDesc) bool {
			return desc.ServiceName == authv1.AuthService_ServiceDesc.ServiceName
		}), handler).Return()

		handler.RegisterService(mockServer)

		mockServer.AssertExpectations(t)
	})

	t.Run("integration test - server accepts registration without error", func(t *testing.T) {
		mockAuthUseCase := new(MockAuthUseCase)
		handler := grpcAdapter.NewAuthHandler(mockAuthUseCase)

		server := grpc.NewServer()

		reflection.Register(server)

		assert.NotPanics(t, func() {
			handler.RegisterService(server)
		}, RegServiceShouldNPanicWithRealServerMsg)

		services := server.GetServiceInfo()
		_, exists := services[authv1.AuthService_ServiceDesc.ServiceName]
		assert.True(t, exists, AuthServiceRegisteredMsg)

		server.Stop()
	})
}
