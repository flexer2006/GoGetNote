package authhandler_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	grpcAdapter "gogetnote/internal/auth/adapters/grpc"
	"gogetnote/internal/auth/domain/services"
	authv1 "gogetnote/pkg/api/auth/v1"
	"gogetnote/pkg/logger"
)

var (
	ErrUserAlreadyExists = errors.New(grpcAdapter.ErrUserAlreadyExistsMsg)
)

func TestRegister(t *testing.T) {
	err := logger.InitGlobalLoggerWithLevel(logger.Development, "debug")
	require.NoError(t, err)

	testCases := []struct {
		name           string
		req            *authv1.RegisterRequest
		setupMock      func(mock *MockAuthUseCase)
		expectedError  error
		validateResult func(t *testing.T, response *authv1.RegisterResponse)
	}{
		{
			name: "successful registration",
			req: &authv1.RegisterRequest{
				Email:    "test@example.com",
				Username: "testuser",
				Password: "password123",
			},
			setupMock: func(mockAuth *MockAuthUseCase) {
				expiresAt := time.Now().Add(24 * time.Hour)
				tokenPair := &services.TokenPair{
					UserID:       "user-123",
					Username:     "testuser",
					AccessToken:  "access-token",
					RefreshToken: "refresh-token",
					ExpiresAt:    expiresAt,
				}
				mockAuth.On("Register", mock.Anything, "test@example.com", "testuser", "password123").Return(tokenPair, nil)
			},
			expectedError: nil,
			validateResult: func(t *testing.T, response *authv1.RegisterResponse) {
				t.Helper()
				assert.NotNil(t, response)
				assert.Equal(t, "user-123", response.UserId)
				assert.Equal(t, "access-token", response.AccessToken)
				assert.Equal(t, "refresh-token", response.RefreshToken)
				assert.NotNil(t, response.ExpiresAt)
			},
		},
		{
			name: "missing email",
			req: &authv1.RegisterRequest{
				Email:    "",
				Username: "testuser",
				Password: "password123",
			},
			setupMock: func(_ *MockAuthUseCase) {
			},
			expectedError: grpcAdapter.ErrInvalidRequest,
			validateResult: func(t *testing.T, response *authv1.RegisterResponse) {
				t.Helper()
				assert.Nil(t, response)
			},
		},
		{
			name: "missing username",
			req: &authv1.RegisterRequest{
				Email:    "test@example.com",
				Username: "",
				Password: "password123",
			},
			setupMock: func(_ *MockAuthUseCase) {
			},
			expectedError: grpcAdapter.ErrInvalidRequest,
			validateResult: func(t *testing.T, response *authv1.RegisterResponse) {
				t.Helper()
				assert.Nil(t, response)
			},
		},
		{
			name: "missing password",
			req: &authv1.RegisterRequest{
				Email:    "test@example.com",
				Username: "testuser",
				Password: "",
			},
			setupMock: func(_ *MockAuthUseCase) {
			},
			expectedError: grpcAdapter.ErrInvalidRequest,
			validateResult: func(t *testing.T, response *authv1.RegisterResponse) {
				t.Helper()
				assert.Nil(t, response)
			},
		},
		{
			name: "user already exists",
			req: &authv1.RegisterRequest{
				Email:    "existing@example.com",
				Username: "existinguser",
				Password: "password123",
			},
			setupMock: func(mockAuth *MockAuthUseCase) {
				mockAuth.On("Register", mock.Anything, "existing@example.com", "existinguser", "password123").
					Return(nil, ErrUserAlreadyExists)
			},
			expectedError: grpcAdapter.ErrUserAlreadyExists,
			validateResult: func(t *testing.T, response *authv1.RegisterResponse) {
				t.Helper()
				assert.Nil(t, response)
			},
		},
		{
			name: "internal service error",
			req: &authv1.RegisterRequest{
				Email:    "test@example.com",
				Username: "testuser",
				Password: "password123",
			},
			setupMock: func(mockAuth *MockAuthUseCase) {
				mockAuth.On("Register", mock.Anything, "test@example.com", "testuser", "password123").
					Return(nil, ErrDatabaseConnection)
			},
			expectedError: grpcAdapter.ErrAuthServiceInternal,
			validateResult: func(t *testing.T, response *authv1.RegisterResponse) {
				t.Helper()
				assert.Nil(t, response)
			},
		},
	}

	for _, tcc := range testCases {
		t.Run(tcc.name, func(t *testing.T) {
			mockAuthUseCase := new(MockAuthUseCase)
			tcc.setupMock(mockAuthUseCase)

			handler := grpcAdapter.NewAuthHandler(mockAuthUseCase)

			ctx := context.Background()
			ctx = logger.NewRequestIDContext(ctx, "test-request-id")

			response, err := handler.Register(ctx, tcc.req)

			if tcc.expectedError != nil {
				require.Error(t, err)
				require.ErrorIs(t, err, tcc.expectedError)
			} else {
				require.NoError(t, err)
			}

			tcc.validateResult(t, response)
			mockAuthUseCase.AssertExpectations(t)
		})
	}
}
