package userhandlergo_test

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"google.golang.org/grpc/metadata"
	"google.golang.org/protobuf/types/known/emptypb"

	grpcAdapter "gogetnote/internal/auth/adapters/grpc"
	"gogetnote/internal/auth/domain/entities"
	"gogetnote/pkg/logger"
)

const (
	validUserID         = "test-user-id-123"
	userIDRetrievedMsg  = "valid userID should be retrieved from context"
	noUserIDExpectedMsg = "no userID should be retrieved in this case"
)

//nolint:gosec
const (
	validTokenMock   = "valid-token-string-for-testing"
	invalidTokenMock = "invalid-token"
)

func TestGetUserIDFromContext(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name              string
		setupContext      func() context.Context
		setupTokenService func(mockSvc *TokenService)
		setupUserUseCase  func(mockUseCase *UserUseCase)
		expectedUserID    string
		expectedOK        bool
		message           string
	}{
		{
			name: "successful userID extraction",
			setupContext: func() context.Context {
				ctx := context.Background()
				ctx = logger.NewContext(ctx, logger.Log(ctx))
				md := metadata.New(map[string]string{
					"authorization": "Bearer " + validTokenMock,
				})
				return metadata.NewIncomingContext(ctx, md)
			},
			setupTokenService: func(mockSvc *TokenService) {
				mockSvc.On("ValidateAccessToken", mock.Anything, validTokenMock).Return(validUserID, nil)
			},
			setupUserUseCase: func(mockUseCase *UserUseCase) {
				mockUseCase.On("GetUserProfile", mock.Anything, validUserID).Return(&entities.User{
					ID:        validUserID,
					Email:     "test@example.com",
					Username:  "testuser",
					CreatedAt: time.Now(),
				}, nil)
			},
			expectedUserID: validUserID,
			expectedOK:     true,
			message:        userIDRetrievedMsg,
		},
		{
			name: "missing metadata",
			setupContext: func() context.Context {
				ctx := context.Background()
				ctx = logger.NewContext(ctx, logger.Log(ctx))
				return ctx
			},
			setupTokenService: func(_ *TokenService) {
			},
			setupUserUseCase: func(_ *UserUseCase) {
			},
			expectedUserID: "",
			expectedOK:     false,
			message:        noUserIDExpectedMsg,
		},
		{
			name: "missing authorization header",
			setupContext: func() context.Context {
				ctx := context.Background()
				ctx = logger.NewContext(ctx, logger.Log(ctx))
				md := metadata.New(map[string]string{})
				return metadata.NewIncomingContext(ctx, md)
			},
			setupTokenService: func(_ *TokenService) {
			},
			setupUserUseCase: func(_ *UserUseCase) {
			},
			expectedUserID: "",
			expectedOK:     false,
			message:        noUserIDExpectedMsg,
		},
		{
			name: "invalid token format - missing Bearer prefix",
			setupContext: func() context.Context {
				ctx := context.Background()
				ctx = logger.NewContext(ctx, logger.Log(ctx))
				md := metadata.New(map[string]string{
					"authorization": validTokenMock,
				})
				return metadata.NewIncomingContext(ctx, md)
			},
			setupTokenService: func(_ *TokenService) {
			},
			setupUserUseCase: func(_ *UserUseCase) {
			},
			expectedUserID: "",
			expectedOK:     false,
			message:        noUserIDExpectedMsg,
		},
		{
			name: "token validation error",
			setupContext: func() context.Context {
				ctx := context.Background()
				ctx = logger.NewContext(ctx, logger.Log(ctx))
				md := metadata.New(map[string]string{
					"authorization": "Bearer " + invalidTokenMock,
				})
				return metadata.NewIncomingContext(ctx, md)
			},
			setupTokenService: func(mockSvc *TokenService) {
				mockSvc.On("ValidateAccessToken", mock.Anything, invalidTokenMock).Return("", errTokenValidation)
			},
			setupUserUseCase: func(_ *UserUseCase) {
			},
			expectedUserID: "",
			expectedOK:     false,
			message:        noUserIDExpectedMsg,
		},
	}

	for _, tc := range testCases {
		tcc := tc
		t.Run(tcc.name, func(t *testing.T) {
			t.Parallel()

			mockTokenSvc := new(TokenService)
			mockUseCase := new(UserUseCase)

			tcc.setupTokenService(mockTokenSvc)
			tcc.setupUserUseCase(mockUseCase)

			handler := grpcAdapter.NewUserHandler(mockUseCase, mockTokenSvc)

			ctx := tcc.setupContext()

			resp, err := handler.GetUserProfile(ctx, &emptypb.Empty{})

			if tcc.expectedOK {
				require.NoError(t, err)
				assert.NotNil(t, resp)
				assert.Equal(t, validUserID, resp.UserId)
			} else {
				require.Error(t, err)
				assert.Contains(t, err.Error(), grpcAdapter.ErrMissingUserIDMsg,
					"Error should be about missing user ID")
				assert.Nil(t, resp)
			}

			mockTokenSvc.AssertExpectations(t)
			mockUseCase.AssertExpectations(t)
		})
	}
}
