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

func TestRefreshTokens(t *testing.T) {
	const (
		userID          = "user-123"
		username        = "testuser"
		refreshToken    = "refresh-token-123"
		newAccessToken  = "new-access-token-123"
		newRefreshToken = "new-refresh-token-456"
	)

	now := time.Now()
	accessExpiry := now.Add(15 * time.Minute)
	refreshExpiry := now.Add(7 * 24 * time.Hour)

	testUser := &entities.User{
		ID:           userID,
		Username:     username,
		Email:        "test@example.com",
		PasswordHash: "hashed_password",
		CreatedAt:    now.Add(-24 * time.Hour),
		UpdatedAt:    now.Add(-24 * time.Hour),
	}

	testTokenObj := &services.RefreshToken{
		ID:        "token-id-123",
		UserID:    userID,
		Token:     refreshToken,
		ExpiresAt: refreshExpiry,
		CreatedAt: now.Add(-24 * time.Hour),
		IsRevoked: false,
	}

	revokedTokenObj := &services.RefreshToken{
		ID:        "token-id-456",
		UserID:    userID,
		Token:     "revoked-token-123",
		ExpiresAt: refreshExpiry,
		CreatedAt: now.Add(-24 * time.Hour),
		IsRevoked: true,
	}

	expectedTokenPair := &services.TokenPair{
		UserID:       userID,
		Username:     username,
		AccessToken:  newAccessToken,
		RefreshToken: newRefreshToken,
		ExpiresAt:    accessExpiry,
	}

	tests := []struct {
		name         string
		refreshToken string
		setupMocks   func(mockUserRepo *mockUserRepository, mockTokenRepo *mockTokenRepository, mockPasswordSvc *mockPasswordService, mockTokenSvc *mockTokenService)
		expectedPair *services.TokenPair
		expectedErr  error
		errorContext string
	}{
		{
			name:         "Success - token refreshed successfully",
			refreshToken: refreshToken,
			setupMocks: func(mockUserRepo *mockUserRepository, mockTokenRepo *mockTokenRepository, mockPasswordSvc *mockPasswordService, mockTokenSvc *mockTokenService) {
				mockTokenRepo.On("FindByToken", mock.Anything, refreshToken).Return(testTokenObj, nil).Once()
				mockUserRepo.On("FindByID", mock.Anything, userID).Return(testUser, nil).Once()
				mockTokenRepo.On("RevokeToken", mock.Anything, refreshToken).Return(nil).Once()
				mockTokenSvc.On("GenerateAccessToken", mock.Anything, userID, username).
					Return(newAccessToken, accessExpiry, nil).Once()
				mockTokenSvc.On("GenerateRefreshToken", mock.Anything, userID).
					Return(newRefreshToken, refreshExpiry, nil).Once()
				mockTokenRepo.On("StoreRefreshToken", mock.Anything, mock.MatchedBy(func(t *services.RefreshToken) bool {
					return t.UserID == userID && t.Token == newRefreshToken && !t.IsRevoked
				})).Return(nil).Once()
			},
			expectedPair: expectedTokenPair,
			expectedErr:  nil,
		},
		{
			name:         "Error - invalid refresh token",
			refreshToken: "invalid-token",
			setupMocks: func(mockUserRepo *mockUserRepository, mockTokenRepo *mockTokenRepository, mockPasswordSvc *mockPasswordService, mockTokenSvc *mockTokenService) {
				mockTokenRepo.On("FindByToken", mock.Anything, "invalid-token").
					Return(nil, errors.New("token not found")).Once()
			},
			expectedPair: nil,
			expectedErr:  services.ErrInvalidRefreshToken,
			errorContext: "finding refresh token",
		},
		{
			name:         "Error - revoked refresh token",
			refreshToken: "revoked-token-123",
			setupMocks: func(mockUserRepo *mockUserRepository, mockTokenRepo *mockTokenRepository, mockPasswordSvc *mockPasswordService, mockTokenSvc *mockTokenService) {
				mockTokenRepo.On("FindByToken", mock.Anything, "revoked-token-123").
					Return(revokedTokenObj, nil).Once()
			},
			expectedPair: nil,
			expectedErr:  services.ErrRevokedRefreshToken,
			errorContext: "token revoked",
		},
		{
			name:         "Error - user not found",
			refreshToken: refreshToken,
			setupMocks: func(mockUserRepo *mockUserRepository, mockTokenRepo *mockTokenRepository, mockPasswordSvc *mockPasswordService, mockTokenSvc *mockTokenService) {
				mockTokenRepo.On("FindByToken", mock.Anything, refreshToken).
					Return(testTokenObj, nil).Once()
				mockUserRepo.On("FindByID", mock.Anything, userID).
					Return(nil, entities.ErrUserNotFound).Once()
			},
			expectedPair: nil,
			expectedErr:  entities.ErrUserNotFound,
			errorContext: "finding user",
		},
		{
			name:         "Error - cannot revoke old token",
			refreshToken: refreshToken,
			setupMocks: func(mockUserRepo *mockUserRepository, mockTokenRepo *mockTokenRepository, mockPasswordSvc *mockPasswordService, mockTokenSvc *mockTokenService) {
				mockTokenRepo.On("FindByToken", mock.Anything, refreshToken).
					Return(testTokenObj, nil).Once()
				mockUserRepo.On("FindByID", mock.Anything, userID).
					Return(testUser, nil).Once()
				mockTokenRepo.On("RevokeToken", mock.Anything, refreshToken).
					Return(errors.New("database error")).Once()
			},
			expectedPair: nil,
			expectedErr:  errors.New("database error"),
			errorContext: "revoking old token",
		},
		{
			name:         "Error - cannot generate new tokens",
			refreshToken: refreshToken,
			setupMocks: func(mockUserRepo *mockUserRepository, mockTokenRepo *mockTokenRepository, mockPasswordSvc *mockPasswordService, mockTokenSvc *mockTokenService) {
				mockTokenRepo.On("FindByToken", mock.Anything, refreshToken).
					Return(testTokenObj, nil).Once()
				mockUserRepo.On("FindByID", mock.Anything, userID).
					Return(testUser, nil).Once()
				mockTokenRepo.On("RevokeToken", mock.Anything, refreshToken).
					Return(nil).Once()
				mockTokenSvc.On("GenerateAccessToken", mock.Anything, userID, username).
					Return("", time.Time{}, errors.New("token generation failed")).Once()
			},
			expectedPair: nil,
			expectedErr:  services.ErrTokenGenerationFailed,
			errorContext: "generating new tokens",
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
			tokenPair, err := authUseCase.RefreshTokens(ctx, tt.refreshToken)

			if tt.expectedErr != nil {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.errorContext)

				if errors.Is(err, services.ErrInvalidRefreshToken) ||
					errors.Is(err, services.ErrRevokedRefreshToken) ||
					errors.Is(err, entities.ErrUserNotFound) ||
					errors.Is(err, services.ErrTokenGenerationFailed) {
					assert.ErrorIs(t, err, tt.expectedErr)
				}

				assert.Nil(t, tokenPair)
			} else {
				require.NoError(t, err)
				assert.NotNil(t, tokenPair)
				assert.Equal(t, tt.expectedPair.UserID, tokenPair.UserID)
				assert.Equal(t, tt.expectedPair.Username, tokenPair.Username)
				assert.Equal(t, tt.expectedPair.AccessToken, tokenPair.AccessToken)
				assert.Equal(t, tt.expectedPair.RefreshToken, tokenPair.RefreshToken)
				assert.Equal(t, tt.expectedPair.ExpiresAt, tokenPair.ExpiresAt)
			}

			mockUserRepo.AssertExpectations(t)
			mockTokenRepo.AssertExpectations(t)
			mockPasswordSvc.AssertExpectations(t)
			mockTokenSvc.AssertExpectations(t)
		})
	}
}
