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
	ErrTokenExpired = errors.New("token has expired")
)

func TestRefreshTokens(t *testing.T) {
	err := logger.InitGlobalLoggerWithLevel(logger.Development, "debug")
	require.NoError(t, err)

	testCases := []struct {
		name           string
		req            *authv1.RefreshTokensRequest
		setupMock      func(mock *MockAuthUseCase)
		expectedError  error
		validateResult func(t *testing.T, response *authv1.RefreshTokensResponse)
	}{
		{
			name: "successful token refresh",
			req: &authv1.RefreshTokensRequest{
				RefreshToken: "valid-refresh-token",
			},
			setupMock: func(mockAuth *MockAuthUseCase) {
				expiresAt := time.Now().Add(24 * time.Hour)
				tokenPair := &services.TokenPair{
					UserID:       "user-123",
					Username:     "testuser",
					AccessToken:  "new-access-token",
					RefreshToken: "new-refresh-token",
					ExpiresAt:    expiresAt,
				}
				mockAuth.On("RefreshTokens", mock.Anything, "valid-refresh-token").Return(tokenPair, nil)
			},
			expectedError: nil,
			validateResult: func(t *testing.T, response *authv1.RefreshTokensResponse) {
				t.Helper()
				assert.NotNil(t, response)
				assert.Equal(t, "new-access-token", response.AccessToken)
				assert.Equal(t, "new-refresh-token", response.RefreshToken)
				assert.NotNil(t, response.ExpiresAt)
				assert.True(t, response.ExpiresAt.AsTime().After(time.Now()))
			},
		},
		{
			name: "missing refresh token",
			req: &authv1.RefreshTokensRequest{
				RefreshToken: "",
			},
			setupMock: func(_ *MockAuthUseCase) {
			},
			expectedError: grpcAdapter.ErrInvalidRequest,
			validateResult: func(t *testing.T, response *authv1.RefreshTokensResponse) {
				t.Helper()
				assert.Nil(t, response)
			},
		},
		{
			name: "invalid refresh token",
			req: &authv1.RefreshTokensRequest{
				RefreshToken: "invalid-token",
			},
			setupMock: func(mockAuth *MockAuthUseCase) {
				mockAuth.On("RefreshTokens", mock.Anything, "invalid-token").
					Return(nil, ErrInvalidToken)
			},
			expectedError: grpcAdapter.ErrInvalidToken,
			validateResult: func(t *testing.T, response *authv1.RefreshTokensResponse) {
				t.Helper()
				assert.Nil(t, response)
			},
		},
		{
			name: "expired refresh token",
			req: &authv1.RefreshTokensRequest{
				RefreshToken: "expired-token",
			},
			setupMock: func(mockAuth *MockAuthUseCase) {
				mockAuth.On("RefreshTokens", mock.Anything, "expired-token").
					Return(nil, ErrTokenExpired)
			},
			expectedError: grpcAdapter.ErrInvalidToken,
			validateResult: func(t *testing.T, response *authv1.RefreshTokensResponse) {
				t.Helper()
				assert.Nil(t, response)
			},
		},
		{
			name: "internal service error",
			req: &authv1.RefreshTokensRequest{
				RefreshToken: "valid-token",
			},
			setupMock: func(mockAuth *MockAuthUseCase) {
				mockAuth.On("RefreshTokens", mock.Anything, "valid-token").
					Return(nil, ErrDatabaseConnection)
			},
			expectedError: grpcAdapter.ErrInvalidToken,
			validateResult: func(t *testing.T, response *authv1.RefreshTokensResponse) {
				t.Helper()
				assert.Nil(t, response)
			},
		},
		{
			name: "full verification of token fields",
			req: &authv1.RefreshTokensRequest{
				RefreshToken: "full-verification-token",
			},
			setupMock: func(mockAuth *MockAuthUseCase) {
				expiresAt := time.Now().Add(24 * time.Hour)
				tokenPair := &services.TokenPair{
					UserID:       "user-456",
					Username:     "fulluser",
					AccessToken:  "complete-access-token",
					RefreshToken: "complete-refresh-token",
					ExpiresAt:    expiresAt,
				}
				mockAuth.On("RefreshTokens", mock.Anything, "full-verification-token").Return(tokenPair, nil)
			},
			expectedError: nil,
			validateResult: func(t *testing.T, response *authv1.RefreshTokensResponse) {
				t.Helper()
				assert.NotNil(t, response)

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

			response, err := handler.RefreshTokens(ctx, tcc.req)

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
