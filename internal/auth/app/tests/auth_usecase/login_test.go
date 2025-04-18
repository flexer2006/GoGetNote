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

func TestLogin(t *testing.T) {
	testEmail := "test@example.com"
	testPassword := "password123"
	userID := "user-123"
	username := "testuser"
	hashedPassword := "hashed_password"

	now := time.Now()
	accessExpiry := now.Add(15 * time.Minute)
	refreshExpiry := now.Add(7 * 24 * time.Hour)

	accessToken := "access-token-123"
	refreshToken := "refresh-token-456"

	testUser := &entities.User{
		ID:           userID,
		Username:     username,
		Email:        testEmail,
		PasswordHash: hashedPassword,
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
		name         string
		email        string
		password     string
		setupMocks   func(mockUserRepo *mockUserRepository, mockTokenRepo *mockTokenRepository, mockPasswordSvc *mockPasswordService, mockTokenSvc *mockTokenService)
		expectedRes  *services.TokenPair
		expectedErr  error
		errorContext string
	}{
		{
			name:     "Success - user logged in successfully",
			email:    testEmail,
			password: testPassword,
			setupMocks: func(mockUserRepo *mockUserRepository, mockTokenRepo *mockTokenRepository, mockPasswordSvc *mockPasswordService, mockTokenSvc *mockTokenService) {
				mockUserRepo.On("FindByEmail", mock.Anything, testEmail).Return(testUser, nil).Once()
				mockPasswordSvc.On("Verify", mock.Anything, testPassword, hashedPassword).Return(true, nil).Once()
				mockTokenSvc.On("GenerateAccessToken", mock.Anything, userID, username).
					Return(accessToken, accessExpiry, nil).Once()
				mockTokenSvc.On("GenerateRefreshToken", mock.Anything, userID).
					Return(refreshToken, refreshExpiry, nil).Once()
				mockTokenRepo.On("StoreRefreshToken", mock.Anything, mock.MatchedBy(func(t *services.RefreshToken) bool {
					return t.UserID == userID && t.Token == refreshToken && !t.IsRevoked
				})).Return(nil).Once()
			},
			expectedRes: expectedTokenPair,
			expectedErr: nil,
		},
		{
			name:     "Error - user not found",
			email:    "nonexistent@example.com",
			password: testPassword,
			setupMocks: func(mockUserRepo *mockUserRepository, mockTokenRepo *mockTokenRepository, mockPasswordSvc *mockPasswordService, mockTokenSvc *mockTokenService) {
				mockUserRepo.On("FindByEmail", mock.Anything, "nonexistent@example.com").
					Return(nil, entities.ErrUserNotFound).Once()
			},
			expectedRes:  nil,
			expectedErr:  services.ErrInvalidCredentials,
			errorContext: "invalid credentials",
		},
		{
			name:     "Error - database error finding user",
			email:    testEmail,
			password: testPassword,
			setupMocks: func(mockUserRepo *mockUserRepository, mockTokenRepo *mockTokenRepository, mockPasswordSvc *mockPasswordService, mockTokenSvc *mockTokenService) {
				mockUserRepo.On("FindByEmail", mock.Anything, testEmail).
					Return(nil, errors.New("database connection error")).Once()
			},
			expectedRes:  nil,
			expectedErr:  errors.New("database connection error"),
			errorContext: "finding user",
		},
		{
			name:     "Error - password verification error",
			email:    testEmail,
			password: testPassword,
			setupMocks: func(mockUserRepo *mockUserRepository, mockTokenRepo *mockTokenRepository, mockPasswordSvc *mockPasswordService, mockTokenSvc *mockTokenService) {
				mockUserRepo.On("FindByEmail", mock.Anything, testEmail).Return(testUser, nil).Once()
				mockPasswordSvc.On("Verify", mock.Anything, testPassword, hashedPassword).
					Return(false, errors.New("password verification error")).Once()
			},
			expectedRes:  nil,
			expectedErr:  errors.New("password verification error"),
			errorContext: "verifying password",
		},
		{
			name:     "Error - invalid password",
			email:    testEmail,
			password: "wrongpassword",
			setupMocks: func(mockUserRepo *mockUserRepository, mockTokenRepo *mockTokenRepository, mockPasswordSvc *mockPasswordService, mockTokenSvc *mockTokenService) {
				mockUserRepo.On("FindByEmail", mock.Anything, testEmail).Return(testUser, nil).Once()
				mockPasswordSvc.On("Verify", mock.Anything, "wrongpassword", hashedPassword).
					Return(false, nil).Once()
			},
			expectedRes:  nil,
			expectedErr:  services.ErrInvalidCredentials,
			errorContext: "invalid credentials",
		},
		{
			name:     "Error - token generation fails",
			email:    testEmail,
			password: testPassword,
			setupMocks: func(mockUserRepo *mockUserRepository, mockTokenRepo *mockTokenRepository, mockPasswordSvc *mockPasswordService, mockTokenSvc *mockTokenService) {
				mockUserRepo.On("FindByEmail", mock.Anything, testEmail).Return(testUser, nil).Once()
				mockPasswordSvc.On("Verify", mock.Anything, testPassword, hashedPassword).Return(true, nil).Once()
				mockTokenSvc.On("GenerateAccessToken", mock.Anything, userID, username).
					Return("", time.Time{}, errors.New("token generation failed")).Once()
			},
			expectedRes:  nil,
			expectedErr:  errors.New("token generation failed"),
			errorContext: "generating tokens",
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
			tokenPair, err := authUseCase.Login(ctx, tt.email, tt.password)

			if tt.expectedErr != nil {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.errorContext)

				if errors.Is(err, services.ErrInvalidCredentials) {
					assert.ErrorIs(t, err, tt.expectedErr)
				}

				assert.Nil(t, tokenPair)
			} else {
				require.NoError(t, err)
				assert.NotNil(t, tokenPair)
				assert.Equal(t, tt.expectedRes.UserID, tokenPair.UserID)
				assert.Equal(t, tt.expectedRes.Username, tokenPair.Username)
				assert.Equal(t, tt.expectedRes.AccessToken, tokenPair.AccessToken)
				assert.Equal(t, tt.expectedRes.RefreshToken, tokenPair.RefreshToken)
				assert.Equal(t, tt.expectedRes.ExpiresAt, tokenPair.ExpiresAt)
			}

			mockUserRepo.AssertExpectations(t)
			mockTokenRepo.AssertExpectations(t)
			mockPasswordSvc.AssertExpectations(t)
			mockTokenSvc.AssertExpectations(t)
		})
	}
}
