package authhandler_test

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"

	grpcAdapter "gogetnote/internal/auth/adapters/grpc"
	"gogetnote/internal/auth/domain/services"
)

const (
	testCreateHandlerWithUseCaseMsg = "should create auth handler with provided auth use case"
	testHandlerShouldNotBeNilMsg    = "handler should not be nil"
	testImplementInterfaceMsg       = "handler should implement required interface"
)

type MockAuthUseCase struct {
	mock.Mock
}

//nolint:wrapcheck
func (m *MockAuthUseCase) Register(ctx context.Context, email, username, password string) (*services.TokenPair, error) {
	args := m.Called(ctx, email, username, password)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	if args.Error(1) == nil {
		return args.Get(0).(*services.TokenPair), nil
	}
	return args.Get(0).(*services.TokenPair), args.Error(1)
}

//nolint:wrapcheck
func (m *MockAuthUseCase) Login(ctx context.Context, email, password string) (*services.TokenPair, error) {
	args := m.Called(ctx, email, password)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	if args.Error(1) == nil {
		return args.Get(0).(*services.TokenPair), nil
	}
	return args.Get(0).(*services.TokenPair), args.Error(1)
}

//nolint:wrapcheck
func (m *MockAuthUseCase) RefreshTokens(ctx context.Context, refreshToken string) (*services.TokenPair, error) {
	args := m.Called(ctx, refreshToken)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	if args.Error(1) == nil {
		return args.Get(0).(*services.TokenPair), nil
	}
	return args.Get(0).(*services.TokenPair), args.Error(1)
}

//nolint:wrapcheck
func (m *MockAuthUseCase) Logout(ctx context.Context, refreshToken string) error {
	args := m.Called(ctx, refreshToken)
	return args.Error(0)
}

func TestNewAuthHandler(t *testing.T) {
	t.Run(testCreateHandlerWithUseCaseMsg, func(t *testing.T) {
		mockAuthUseCase := new(MockAuthUseCase)
		handler := grpcAdapter.NewAuthHandler(mockAuthUseCase)

		assert.NotNil(t, handler, testHandlerShouldNotBeNilMsg)
	})

	t.Run(testImplementInterfaceMsg, func(_ *testing.T) {
		mockAuthUseCase := new(MockAuthUseCase)

		handler := grpcAdapter.NewAuthHandler(mockAuthUseCase)

		var _ any = handler
	})
}
