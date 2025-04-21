package authhandler_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/timestamppb"

	grpcAdapter "gogetnote/internal/auth/adapters/grpc"
	"gogetnote/internal/auth/domain/services"
	authv1 "gogetnote/pkg/api/auth/v1"
	"gogetnote/pkg/logger"
)

var (
	ErrInvalidCredentials = errors.New("invalid credentials")
	ErrUserNotFound       = errors.New("user not found")
	ErrDatabaseConnection = errors.New("database connection error")
)

func TestLogin(t *testing.T) {
	err := logger.InitGlobalLoggerWithLevel(logger.Development, "debug")
	require.NoError(t, err)

	testCases := []struct {
		name           string
		req            *authv1.LoginRequest
		setupMock      func(mock *MockAuthUseCase)
		expectedError  error
		validateResult func(t *testing.T, response *authv1.LoginResponse)
	}{
		{
			name: "successful login",
			req: &authv1.LoginRequest{
				Email:    "test@example.com",
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
				mockAuth.On("Login", mock.Anything, "test@example.com", "password123").Return(tokenPair, nil)
			},
			expectedError: nil,
			validateResult: func(t *testing.T, response *authv1.LoginResponse) {
				t.Helper()
				assert.NotNil(t, response)
				assert.Equal(t, "user-123", response.UserId)
				assert.Equal(t, "testuser", response.Username)
				assert.Equal(t, "access-token", response.AccessToken)
				assert.Equal(t, "refresh-token", response.RefreshToken)
				assert.NotNil(t, response.ExpiresAt)

				assert.True(t, response.ExpiresAt.AsTime().After(time.Now()))
			},
		},
		{
			name: "missing email",
			req: &authv1.LoginRequest{
				Email:    "",
				Password: "password123",
			},
			setupMock: func(_ *MockAuthUseCase) {
			},
			expectedError: grpcAdapter.ErrInvalidRequest,
			validateResult: func(t *testing.T, response *authv1.LoginResponse) {
				t.Helper()
				assert.Nil(t, response)
			},
		},
		{
			name: "missing password",
			req: &authv1.LoginRequest{
				Email:    "test@example.com",
				Password: "",
			},
			setupMock: func(_ *MockAuthUseCase) {
			},
			expectedError: grpcAdapter.ErrInvalidRequest,
			validateResult: func(t *testing.T, response *authv1.LoginResponse) {
				t.Helper()
				assert.Nil(t, response)
			},
		},
		{
			name: "invalid credentials",
			req: &authv1.LoginRequest{
				Email:    "test@example.com",
				Password: "wrongpassword",
			},
			setupMock: func(mockAuth *MockAuthUseCase) {
				mockAuth.On("Login", mock.Anything, "test@example.com", "wrongpassword").
					Return(nil, ErrInvalidCredentials)
			},
			expectedError: grpcAdapter.ErrInvalidCredentials,
			validateResult: func(t *testing.T, response *authv1.LoginResponse) {
				t.Helper()
				assert.Nil(t, response)
			},
		},
		{
			name: "user not found",
			req: &authv1.LoginRequest{
				Email:    "nonexistent@example.com",
				Password: "password123",
			},
			setupMock: func(mockAuth *MockAuthUseCase) {
				mockAuth.On("Login", mock.Anything, "nonexistent@example.com", "password123").
					Return(nil, ErrUserNotFound)
			},
			expectedError: grpcAdapter.ErrInvalidCredentials,
			validateResult: func(t *testing.T, response *authv1.LoginResponse) {
				t.Helper()
				assert.Nil(t, response)
			},
		},
		{
			name: "internal service error",
			req: &authv1.LoginRequest{
				Email:    "test@example.com",
				Password: "password123",
			},
			setupMock: func(mockAuth *MockAuthUseCase) {
				mockAuth.On("Login", mock.Anything, "test@example.com", "password123").
					Return(nil, ErrDatabaseConnection)
			},
			expectedError: grpcAdapter.ErrInvalidCredentials,
			validateResult: func(t *testing.T, response *authv1.LoginResponse) {
				t.Helper()
				assert.Nil(t, response)
			},
		},
		{
			name: "all fields populated correctly",
			req: &authv1.LoginRequest{
				Email:    "complete@example.com",
				Password: "fullpassword",
			},
			setupMock: func(mockAuth *MockAuthUseCase) {
				expiresAt := time.Now().Add(24 * time.Hour)
				tokenPair := &services.TokenPair{
					UserID:       "user-complete",
					Username:     "completeuser",
					AccessToken:  "complete-access-token",
					RefreshToken: "complete-refresh-token",
					ExpiresAt:    expiresAt,
				}
				mockAuth.On("Login", mock.Anything, "complete@example.com", "fullpassword").Return(tokenPair, nil)
			},
			expectedError: nil,
			validateResult: func(t *testing.T, response *authv1.LoginResponse) {
				t.Helper()
				assert.NotNil(t, response)

				assert.Equal(t, "user-complete", response.UserId)
				assert.Equal(t, "completeuser", response.Username)
				assert.Equal(t, "complete-access-token", response.AccessToken)
				assert.Equal(t, "complete-refresh-token", response.RefreshToken)

				assert.NotNil(t, response.ExpiresAt)
				assert.IsType(t, &timestamppb.Timestamp{}, response.ExpiresAt)
				assert.True(t, response.ExpiresAt.AsTime().After(time.Now()))
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

			response, err := handler.Login(ctx, tcc.req)

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
