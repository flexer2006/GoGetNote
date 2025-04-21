package userhandlergo_test

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"google.golang.org/grpc/metadata"
	"google.golang.org/protobuf/types/known/emptypb"

	grpcAdapter "gogetnote/internal/auth/adapters/grpc"
	"gogetnote/internal/auth/domain/entities"
	authv1 "gogetnote/pkg/api/auth/v1"
	"gogetnote/pkg/logger"
)

const (
	testUserID   = "test-user-id"
	testEmail    = "test@example.com"
	testUsername = "testuser"
	testToken    = "valid-token"
)

var (
	errTokenValidation = errors.New("token validation failed")
	errUnexpected      = errors.New("unexpected error")
)

func TestGetUserProfile(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name           string
		setupMocks     func(mockUseCase *UserUseCase, mockTokenSvc *TokenService)
		setupContext   func() context.Context
		expectedError  error
		validateResult func(t *testing.T, result interface{}, err error)
	}{
		{
			name: "successful get user profile",
			setupMocks: func(mockUseCase *UserUseCase, mockTokenSvc *TokenService) {
				createdAt := time.Now()
				mockTokenSvc.On("ValidateAccessToken", mock.Anything, testToken).Return(testUserID, nil)
				mockUseCase.On("GetUserProfile", mock.Anything, testUserID).Return(&entities.User{
					ID:        testUserID,
					Email:     testEmail,
					Username:  testUsername,
					CreatedAt: createdAt,
				}, nil)
			},
			setupContext: func() context.Context {
				ctx := context.Background()
				ctx = logger.NewContext(ctx, logger.Log(ctx))
				md := metadata.New(map[string]string{
					"authorization": "Bearer " + testToken,
				})
				return metadata.NewIncomingContext(ctx, md)
			},
			expectedError: nil,
			validateResult: func(t *testing.T, result interface{}, err error) {
				t.Helper()
				require.NoError(t, err)
				assert.NotNil(t, result)
				response := result.(*authv1.UserProfileResponse)
				assert.Equal(t, testUserID, response.UserId)
				assert.Equal(t, testEmail, response.Email)
				assert.Equal(t, testUsername, response.Username)
				assert.NotNil(t, response.CreatedAt)
			},
		},
		{
			name: "missing metadata",
			setupMocks: func(_ *UserUseCase, _ *TokenService) {
			},
			setupContext: func() context.Context {
				ctx := context.Background()
				ctx = logger.NewContext(ctx, logger.Log(ctx))
				return ctx
			},
			expectedError: grpcAdapter.ErrMissingUserID,
			validateResult: func(t *testing.T, result interface{}, err error) {
				t.Helper()
				require.Error(t, err)
				assert.Nil(t, result)
				assert.ErrorIs(t, err, grpcAdapter.ErrMissingUserID)
			},
		},
		{
			name: "missing authorization header",
			setupMocks: func(_ *UserUseCase, _ *TokenService) {
			},
			setupContext: func() context.Context {
				ctx := context.Background()
				ctx = logger.NewContext(ctx, logger.Log(ctx))
				md := metadata.New(map[string]string{})
				return metadata.NewIncomingContext(ctx, md)
			},
			expectedError: grpcAdapter.ErrMissingUserID,
			validateResult: func(t *testing.T, result interface{}, err error) {
				t.Helper()
				require.Error(t, err)
				assert.Nil(t, result)
				assert.ErrorIs(t, err, grpcAdapter.ErrMissingUserID)
			},
		},
		{
			name: "invalid token format",
			setupMocks: func(_ *UserUseCase, _ *TokenService) {
			},
			setupContext: func() context.Context {
				ctx := context.Background()
				ctx = logger.NewContext(ctx, logger.Log(ctx))
				md := metadata.New(map[string]string{
					"authorization": "InvalidFormat",
				})
				return metadata.NewIncomingContext(ctx, md)
			},
			expectedError: grpcAdapter.ErrMissingUserID,
			validateResult: func(t *testing.T, result interface{}, err error) {
				t.Helper()
				require.Error(t, err)
				assert.Nil(t, result)
				assert.ErrorIs(t, err, grpcAdapter.ErrMissingUserID)
			},
		},
		{
			name: "token validation fails",
			setupMocks: func(_ *UserUseCase, mockTokenSvc *TokenService) {
				mockTokenSvc.On("ValidateAccessToken", mock.Anything, testToken).Return("", errTokenValidation)
			},
			setupContext: func() context.Context {
				ctx := context.Background()
				ctx = logger.NewContext(ctx, logger.Log(ctx))
				md := metadata.New(map[string]string{
					"authorization": "Bearer " + testToken,
				})
				return metadata.NewIncomingContext(ctx, md)
			},
			expectedError: grpcAdapter.ErrMissingUserID,
			validateResult: func(t *testing.T, result interface{}, err error) {
				t.Helper()
				require.Error(t, err)
				assert.Nil(t, result)
				assert.ErrorIs(t, err, grpcAdapter.ErrMissingUserID)
			},
		},
		{
			name: "user not found",
			setupMocks: func(mockUseCase *UserUseCase, mockTokenSvc *TokenService) {
				mockTokenSvc.On("ValidateAccessToken", mock.Anything, testToken).Return(testUserID, nil)
				mockUseCase.On("GetUserProfile", mock.Anything, testUserID).Return(nil, fmt.Errorf("%w", grpcAdapter.ErrUserNotFound))
			},
			setupContext: func() context.Context {
				ctx := context.Background()
				ctx = logger.NewContext(ctx, logger.Log(ctx))
				md := metadata.New(map[string]string{
					"authorization": "Bearer " + testToken,
				})
				return metadata.NewIncomingContext(ctx, md)
			},
			expectedError: grpcAdapter.ErrUserNotFound,
			validateResult: func(t *testing.T, result interface{}, err error) {
				t.Helper()
				require.Error(t, err)
				assert.Nil(t, result)
				assert.ErrorIs(t, err, grpcAdapter.ErrUserNotFound)
			},
		},
		{
			name: "internal service error",
			setupMocks: func(mockUseCase *UserUseCase, mockTokenSvc *TokenService) {
				mockTokenSvc.On("ValidateAccessToken", mock.Anything, testToken).Return(testUserID, nil)
				mockUseCase.On("GetUserProfile", mock.Anything, testUserID).Return(nil, errUnexpected)
			},
			setupContext: func() context.Context {
				ctx := context.Background()
				ctx = logger.NewContext(ctx, logger.Log(ctx))
				md := metadata.New(map[string]string{
					"authorization": "Bearer " + testToken,
				})
				return metadata.NewIncomingContext(ctx, md)
			},
			expectedError: grpcAdapter.ErrInternalService,
			validateResult: func(t *testing.T, result interface{}, err error) {
				t.Helper()
				require.Error(t, err)
				assert.Nil(t, result)
				assert.ErrorIs(t, err, grpcAdapter.ErrInternalService)
			},
		},
	}

	for _, tc := range testCases {
		tcc := tc
		t.Run(tcc.name, func(t *testing.T) {
			t.Parallel()

			mockUseCase := new(UserUseCase)
			mockTokenSvc := new(TokenService)

			tcc.setupMocks(mockUseCase, mockTokenSvc)

			handler := grpcAdapter.NewUserHandler(mockUseCase, mockTokenSvc)
			ctx := tcc.setupContext()

			result, err := handler.GetUserProfile(ctx, &emptypb.Empty{})

			tcc.validateResult(t, result, err)
			mockUseCase.AssertExpectations(t)
			mockTokenSvc.AssertExpectations(t)
		})
	}
}
