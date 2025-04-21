package userhandlergo_test

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"google.golang.org/grpc"

	grpcAdapter "gogetnote/internal/auth/adapters/grpc"
	"gogetnote/internal/auth/domain/entities"
	authv1 "gogetnote/pkg/api/auth/v1"
)

const (
	userServiceRegisteredMsg = "user service should be registered with gRPC server"
	regService               = "RegisterService"
)

type mockGrpcServer struct {
	mock.Mock
}
type TokenService struct {
	mock.Mock
}
type UserUseCase struct {
	mock.Mock
}

func (m *UserUseCase) GetUserProfile(ctx context.Context, userID string) (*entities.User, error) {
	args := m.Called(ctx, userID)

	var user *entities.User
	if args.Get(0) != nil {
		user = args.Get(0).(*entities.User)
	}

	if err := args.Error(1); err != nil {
		return user, fmt.Errorf("mock GetUserProfile error: %w", err)
	}
	return user, nil
}

func (m *TokenService) GenerateAccessToken(ctx context.Context, userID, username string) (string, time.Time, error) {
	args := m.Called(ctx, userID, username)
	return args.String(0), args.Get(1).(time.Time), args.Error(2)
}

func (m *TokenService) GenerateRefreshToken(ctx context.Context, userID string) (string, time.Time, error) {
	args := m.Called(ctx, userID)
	return args.String(0), args.Get(1).(time.Time), args.Error(2)
}

func (m *TokenService) ValidateAccessToken(ctx context.Context, token string) (string, error) {
	args := m.Called(ctx, token)
	return args.String(0), args.Error(1)
}

func (m *mockGrpcServer) RegisterService(desc *grpc.ServiceDesc, impl interface{}) {
	m.Called(desc, impl)
}

func TestUserHandlerRegisterService(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name string
	}{
		{
			name: "successfully register user service",
		},
	}

	for _, tc := range testCases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			mockUseCase := new(UserUseCase)
			mockTokenSvc := new(TokenService)
			mockServer := new(mockGrpcServer)

			mockServer.On(
				regService,
				&authv1.UserService_ServiceDesc,
				mock.AnythingOfType("*grpc.UserHandler"),
			).Return()

			handler := grpcAdapter.NewUserHandler(mockUseCase, mockTokenSvc)
			handler.RegisterService(mockServer)

			mockServer.AssertCalled(t, regService, &authv1.UserService_ServiceDesc, handler)

			assert.True(t, mockServer.AssertNumberOfCalls(t, regService, 1), userServiceRegisteredMsg)
		})
	}
}
