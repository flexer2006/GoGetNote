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
			name: "Success - tokens generated and stored successfully",
			user: testUser,
			setupMocks: func(mockUserRepo *mockUserRepository, mockTokenRepo *mockTokenRepository, mockPasswordSvc *mockPasswordService, mockTokenSvc *mockTokenService) {
				mockTokenSvc.On("GenerateAccessToken", mock.Anything, userID, username).
					Return(accessToken, accessExpiry, nil).Once()

				mockTokenSvc.On("GenerateRefreshToken", mock.Anything, userID).
					Return(refreshToken, refreshExpiry, nil).Once()

				mockTokenRepo.On("StoreRefreshToken", mock.Anything, mock.MatchedBy(func(t *services.RefreshToken) bool {
					return t.UserID == userID &&
						t.Token == refreshToken &&
						t.ExpiresAt == refreshExpiry &&
						!t.IsRevoked
				})).Return(nil).Once()
			},
			expectedRes: expectedTokenPair,
			expectedErr: nil,
		},
		{
			name: "Error - access token generation fails",
			user: testUser,
			setupMocks: func(mockUserRepo *mockUserRepository, mockTokenRepo *mockTokenRepository, mockPasswordSvc *mockPasswordService, mockTokenSvc *mockTokenService) {
				mockTokenSvc.On("GenerateAccessToken", mock.Anything, userID, username).
					Return("", time.Time{}, errors.New("token generation failed")).Once()
			},
			expectedRes: nil,
			expectedErr: services.ErrTokenGenerationFailed,
		},
		{
			name: "Error - refresh token generation fails",
			user: testUser,
			setupMocks: func(mockUserRepo *mockUserRepository, mockTokenRepo *mockTokenRepository, mockPasswordSvc *mockPasswordService, mockTokenSvc *mockTokenService) {
				mockTokenSvc.On("GenerateAccessToken", mock.Anything, userID, username).
					Return(accessToken, accessExpiry, nil).Once()

				mockTokenSvc.On("GenerateRefreshToken", mock.Anything, userID).
					Return("", time.Time{}, errors.New("token generation failed")).Once()
			},
			expectedRes: nil,
			expectedErr: services.ErrTokenGenerationFailed,
		},
		{
			name: "Error - storing refresh token fails",
			user: testUser,
			setupMocks: func(mockUserRepo *mockUserRepository, mockTokenRepo *mockTokenRepository, mockPasswordSvc *mockPasswordService, mockTokenSvc *mockTokenService) {
				mockTokenSvc.On("GenerateAccessToken", mock.Anything, userID, username).
					Return(accessToken, accessExpiry, nil).Once()

				mockTokenSvc.On("GenerateRefreshToken", mock.Anything, userID).
					Return(refreshToken, refreshExpiry, nil).Once()

				mockTokenRepo.On("StoreRefreshToken", mock.Anything, mock.Anything).
					Return(errors.New("database error")).Once()
			},
			expectedRes: nil,
			expectedErr: errors.New("database error"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockUserRepo := new(mockUserRepository)
			mockTokenRepo := new(mockTokenRepository)
			mockPasswordSvc := new(mockPasswordService)
			mockTokenSvc := new(mockTokenService)

			tt.setupMocks(mockUserRepo, mockTokenRepo, mockPasswordSvc, mockTokenSvc)

			authUseCase := app.NewAuthUseCase(mockUserRepo, mockTokenRepo, mockPasswordSvc, mockTokenSvc)

			ctx := context.Background()

			if tt.expectedErr == nil {
				mockUserRepo.On("FindByEmail", mock.Anything, tt.user.Email).
					Return(nil, entities.ErrUserNotFound).Once()

				mockPasswordSvc.On("Hash", mock.Anything, testPassword).
					Return("hashed_password", nil).Once()

				mockUserRepo.On("Create", mock.Anything, mock.Anything).
					Return(tt.user, nil).Once()

				tokenPair, err := authUseCase.Register(ctx, tt.user.Email, tt.user.Username, testPassword)

				require.NoError(t, err)
				assert.Equal(t, tt.expectedRes.UserID, tokenPair.UserID)
				assert.Equal(t, tt.expectedRes.Username, tokenPair.Username)
				assert.Equal(t, tt.expectedRes.AccessToken, tokenPair.AccessToken)
				assert.Equal(t, tt.expectedRes.RefreshToken, tokenPair.RefreshToken)
				assert.Equal(t, tt.expectedRes.ExpiresAt, tokenPair.ExpiresAt)
			} else {
				mockUserRepo.On("FindByEmail", mock.Anything, tt.user.Email).
					Return(tt.user, nil).Once()

				mockPasswordSvc.On("Verify", mock.Anything, testPassword, tt.user.PasswordHash).
					Return(true, nil).Once()

				tokenPair, err := authUseCase.Login(ctx, tt.user.Email, testPassword)

				require.Error(t, err)
				if errors.Is(err, services.ErrTokenGenerationFailed) {
					assert.ErrorIs(t, err, tt.expectedErr)
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
