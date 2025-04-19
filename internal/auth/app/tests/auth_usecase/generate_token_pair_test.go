package authusecase_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"gogetnote/internal/auth/app"
	"gogetnote/internal/auth/domain/entities"
	"gogetnote/internal/auth/domain/services"
)

var (
	ErrDatabaseOperation = errors.New("database error")
)

func TestGenerateTokenPair(t *testing.T) {
	userID := "test-user-id"
	username := "testuser"
	accessToken := "access-token-123"
	refreshToken := "refresh-token-456"
	now := time.Now()
	accessExpiry := now.Add(15 * time.Minute)
	refreshExpiry := now.Add(7 * 24 * time.Hour)
	testPassword := "password123"

	testUser := &entities.User{
		ID:           userID,
		Username:     username,
		Email:        "test@example.com",
		PasswordHash: "hashed_password",
		CreatedAt:    now.Add(-24 * time.Hour),
		UpdatedAt:    now.Add(-24 * time.Hour),
	}

	expectedTokenPair := &services.TokenPair{
		UserID:       userID,
		Username:     username,
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		ExpiresAt:    accessExpiry,
	}

	tests := []struct {
		name        string
		user        *entities.User
		setupMocks  func(mockUserRepo *mockUserRepository, mockTokenRepo *mockTokenRepository, mockPasswordSvc *mockPasswordService, mockTokenSvc *mockTokenService)
		expectedRes *services.TokenPair
		expectedErr error
	}{
		{
			name: "success - tokens generated and stored successfully",
			user: testUser,
			setupMocks: func(_ *mockUserRepository, mockTokenRepo *mockTokenRepository, _ *mockPasswordService, mockTokenSvc *mockTokenService) {
				mockTokenSvc.On("GenerateAccessToken", mock.Anything, userID, username).
					Return(accessToken, accessExpiry, nil).Once()

				mockTokenSvc.On("GenerateRefreshToken", mock.Anything, userID).
					Return(refreshToken, refreshExpiry, nil).Once()

				mockTokenRepo.On("StoreRefreshToken", mock.Anything, mock.MatchedBy(func(t *services.RefreshToken) bool {
					return t.UserID == userID &&
						t.Token == refreshToken &&
						t.ExpiresAt.Equal(refreshExpiry) &&
						!t.IsRevoked
				})).Return(nil).Once()
			},
			expectedRes: expectedTokenPair,
			expectedErr: nil,
		},
		{
			name: "error - access token generation fails",
			user: testUser,
			setupMocks: func(_ *mockUserRepository, _ *mockTokenRepository, _ *mockPasswordService, mockTokenSvc *mockTokenService) {
				mockTokenSvc.On("GenerateAccessToken", mock.Anything, userID, username).
					Return("", time.Time{}, services.ErrTokenGenerationFailed).Once()
			},
			expectedRes: nil,
			expectedErr: services.ErrTokenGenerationFailed,
		},
		{
			name: "error - refresh token generation fails",
			user: testUser,
			setupMocks: func(_ *mockUserRepository, _ *mockTokenRepository, _ *mockPasswordService, mockTokenSvc *mockTokenService) {
				mockTokenSvc.On("GenerateAccessToken", mock.Anything, userID, username).
					Return(accessToken, accessExpiry, nil).Once()

				mockTokenSvc.On("GenerateRefreshToken", mock.Anything, userID).
					Return("", time.Time{}, services.ErrTokenGenerationFailed).Once()
			},
			expectedRes: nil,
			expectedErr: services.ErrTokenGenerationFailed,
		},
		{
			name: "error - storing refresh token fails",
			user: testUser,
			setupMocks: func(_ *mockUserRepository, mockTokenRepo *mockTokenRepository, _ *mockPasswordService, mockTokenSvc *mockTokenService) {
				mockTokenSvc.On("GenerateAccessToken", mock.Anything, userID, username).
					Return(accessToken, accessExpiry, nil).Once()

				mockTokenSvc.On("GenerateRefreshToken", mock.Anything, userID).
					Return(refreshToken, refreshExpiry, nil).Once()

				mockTokenRepo.On("StoreRefreshToken", mock.Anything, mock.Anything).
					Return(ErrDatabaseOperation).Once()
			},
			expectedRes: nil,
			expectedErr: ErrDatabaseOperation,
		},
	}

	for _, ttt := range tests {
		t.Run(ttt.name, func(t *testing.T) {
			mockUserRepo := new(mockUserRepository)
			mockTokenRepo := new(mockTokenRepository)
			mockPasswordSvc := new(mockPasswordService)
			mockTokenSvc := new(mockTokenService)

			ttt.setupMocks(mockUserRepo, mockTokenRepo, mockPasswordSvc, mockTokenSvc)

			authUseCase := app.NewAuthUseCase(mockUserRepo, mockTokenRepo, mockPasswordSvc, mockTokenSvc)

			ctx := context.Background()

			if ttt.expectedErr == nil {
				mockUserRepo.On("FindByEmail", mock.Anything, ttt.user.Email).
					Return(nil, entities.ErrUserNotFound).Once()

				mockPasswordSvc.On("Hash", mock.Anything, testPassword).
					Return("hashed_password", nil).Once()

				mockUserRepo.On("Create", mock.Anything, mock.Anything).
					Return(ttt.user, nil).Once()

				tokenPair, err := authUseCase.Register(ctx, ttt.user.Email, ttt.user.Username, testPassword)

				require.NoError(t, err)
				assert.Equal(t, ttt.expectedRes.UserID, tokenPair.UserID)
				assert.Equal(t, ttt.expectedRes.Username, tokenPair.Username)
				assert.Equal(t, ttt.expectedRes.AccessToken, tokenPair.AccessToken)
				assert.Equal(t, ttt.expectedRes.RefreshToken, tokenPair.RefreshToken)
				assert.Equal(t, ttt.expectedRes.ExpiresAt, tokenPair.ExpiresAt)
			} else {
				mockUserRepo.On("FindByEmail", mock.Anything, ttt.user.Email).
					Return(ttt.user, nil).Once()

				mockPasswordSvc.On("Verify", mock.Anything, testPassword, ttt.user.PasswordHash).
					Return(true, nil).Once()

				tokenPair, err := authUseCase.Login(ctx, ttt.user.Email, testPassword)

				require.Error(t, err)
				if errors.Is(err, services.ErrTokenGenerationFailed) {
					assert.ErrorIs(t, err, ttt.expectedErr)
				}
				assert.Nil(t, tokenPair)
			}

			mockUserRepo.AssertExpectations(t)
			mockTokenRepo.AssertExpectations(t)
			mockPasswordSvc.AssertExpectations(t)
			mockTokenSvc.AssertExpectations(t)
		})
	}
}
