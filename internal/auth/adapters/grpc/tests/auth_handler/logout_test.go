package authhandler_test

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/emptypb"

	grpcAdapter "gogetnote/internal/auth/adapters/grpc"
	authv1 "gogetnote/pkg/api/auth/v1"
	"gogetnote/pkg/logger"
)

var (
	ErrInvalidToken = errors.New(grpcAdapter.ErrInvalidTokenMsg)
)

func TestLogout(t *testing.T) {
	err := logger.InitGlobalLoggerWithLevel(logger.Development, "debug")
	require.NoError(t, err)

	testCases := []struct {
		name          string
		req           *authv1.LogoutRequest
		setupMock     func(mock *MockAuthUseCase)
		expectedError error
	}{
		{
			name: "successful logout",
			req: &authv1.LogoutRequest{
				RefreshToken: "valid-refresh-token",
			},
			setupMock: func(mockAuth *MockAuthUseCase) {
				mockAuth.On("Logout", mock.Anything, "valid-refresh-token").Return(nil)
			},
			expectedError: nil,
		},
		{
			name: "missing refresh token",
			req: &authv1.LogoutRequest{
				RefreshToken: "",
			},
			setupMock: func(_ *MockAuthUseCase) {
			},
			expectedError: grpcAdapter.ErrInvalidRequest,
		},
		{
			name: "invalid refresh token",
			req: &authv1.LogoutRequest{
				RefreshToken: "invalid-token",
			},
			setupMock: func(mockAuth *MockAuthUseCase) {
				mockAuth.On("Logout", mock.Anything, "invalid-token").
					Return(ErrInvalidToken)
			},
			expectedError: grpcAdapter.ErrInvalidToken,
		},
		{
			name: "expired refresh token",
			req: &authv1.LogoutRequest{
				RefreshToken: "expired-token",
			},
			setupMock: func(mockAuth *MockAuthUseCase) {
				mockAuth.On("Logout", mock.Anything, "expired-token").
					Return(ErrInvalidToken)
			},
			expectedError: grpcAdapter.ErrInvalidToken,
		},
		{
			name: "internal service error",
			req: &authv1.LogoutRequest{
				RefreshToken: "valid-token",
			},
			setupMock: func(mockAuth *MockAuthUseCase) {
				mockAuth.On("Logout", mock.Anything, "valid-token").
					Return(ErrDatabaseConnection)
			},
			expectedError: grpcAdapter.ErrAuthServiceInternal,
		},
	}

	for _, tcc := range testCases {
		t.Run(tcc.name, func(t *testing.T) {
			mockAuthUseCase := new(MockAuthUseCase)
			tcc.setupMock(mockAuthUseCase)

			handler := grpcAdapter.NewAuthHandler(mockAuthUseCase)

			ctx := context.Background()
			ctx = logger.NewRequestIDContext(ctx, "test-request-id")

			response, err := handler.Logout(ctx, tcc.req)

			if tcc.expectedError != nil {
				require.Error(t, err)
				require.ErrorIs(t, err, tcc.expectedError)
				assert.Nil(t, response)
			} else {
				require.NoError(t, err)
				assert.NotNil(t, response)
				assert.IsType(t, &emptypb.Empty{}, response)
			}

			mockAuthUseCase.AssertExpectations(t)
		})
	}
}
