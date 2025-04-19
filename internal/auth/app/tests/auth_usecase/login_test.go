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
	ErrDatabaseConnection   = errors.New("database connection error")
	ErrPasswordVerification = errors.New("password verification error")
	ErrTokenGeneration      = errors.New("token generation failed")
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
			name:     "success - user logged in successfully",
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
			name:     "error - user not found",
			email:    "nonexistent@example.com",
			password: testPassword,
			setupMocks: func(mockUserRepo *mockUserRepository, _ *mockTokenRepository, _ *mockPasswordService, _ *mockTokenService) {
				mockUserRepo.On("FindByEmail", mock.Anything, "nonexistent@example.com").
					Return(nil, entities.ErrUserNotFound).Once()
			},
			expectedRes:  nil,
			expectedErr:  services.ErrInvalidCredentials,
			errorContext: "invalid credentials",
		},
		{
			name:     "error - database error finding user",
			email:    testEmail,
			password: testPassword,
			setupMocks: func(mockUserRepo *mockUserRepository, _ *mockTokenRepository, _ *mockPasswordService, _ *mockTokenService) {
				mockUserRepo.On("FindByEmail", mock.Anything, testEmail).
					Return(nil, ErrDatabaseConnection).Once()
			},
			expectedRes:  nil,
			expectedErr:  ErrDatabaseConnection,
			errorContext: "finding user",
		},
		{
			name:     "error - password verification error",
			email:    testEmail,
			password: testPassword,
			setupMocks: func(mockUserRepo *mockUserRepository, _ *mockTokenRepository, mockPasswordSvc *mockPasswordService, _ *mockTokenService) {
				mockUserRepo.On("FindByEmail", mock.Anything, testEmail).Return(testUser, nil).Once()
				mockPasswordSvc.On("Verify", mock.Anything, testPassword, hashedPassword).
					Return(false, ErrPasswordVerification).Once()
			},
			expectedRes:  nil,
			expectedErr:  ErrPasswordVerification,
			errorContext: "verifying password",
		},
		{
			name:     "error - invalid password",
			email:    testEmail,
			password: "wrongpassword",
			setupMocks: func(mockUserRepo *mockUserRepository, _ *mockTokenRepository, mockPasswordSvc *mockPasswordService, _ *mockTokenService) {
				mockUserRepo.On("FindByEmail", mock.Anything, testEmail).Return(testUser, nil).Once()
				mockPasswordSvc.On("Verify", mock.Anything, "wrongpassword", hashedPassword).
					Return(false, nil).Once()
			},
			expectedRes:  nil,
			expectedErr:  services.ErrInvalidCredentials,
			errorContext: "invalid credentials",
		},
		{
			name:     "error - token generation fails",
			email:    testEmail,
			password: testPassword,
			setupMocks: func(mockUserRepo *mockUserRepository, _ *mockTokenRepository, mockPasswordSvc *mockPasswordService, mockTokenSvc *mockTokenService) {
				mockUserRepo.On("FindByEmail", mock.Anything, testEmail).Return(testUser, nil).Once()
				mockPasswordSvc.On("Verify", mock.Anything, testPassword, hashedPassword).Return(true, nil).Once()
				mockTokenSvc.On("GenerateAccessToken", mock.Anything, userID, username).
					Return("", time.Time{}, ErrTokenGeneration).Once()
			},
			expectedRes:  nil,
			expectedErr:  ErrTokenGeneration,
			errorContext: "generating tokens",
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
			tokenPair, err := authUseCase.Login(ctx, ttt.email, ttt.password)

			if ttt.expectedErr != nil {
				require.Error(t, err)
				assert.Contains(t, err.Error(), ttt.errorContext)

				if errors.Is(err, services.ErrInvalidCredentials) {
					assert.ErrorIs(t, err, ttt.expectedErr)
				}

				assert.Nil(t, tokenPair)
			} else {
				require.NoError(t, err)
				assert.NotNil(t, tokenPair)
				assert.Equal(t, ttt.expectedRes.UserID, tokenPair.UserID)
				assert.Equal(t, ttt.expectedRes.Username, tokenPair.Username)
				assert.Equal(t, ttt.expectedRes.AccessToken, tokenPair.AccessToken)
				assert.Equal(t, ttt.expectedRes.RefreshToken, tokenPair.RefreshToken)
				assert.Equal(t, ttt.expectedRes.ExpiresAt, tokenPair.ExpiresAt)
			}

			mockUserRepo.AssertExpectations(t)
			mockTokenRepo.AssertExpectations(t)
			mockPasswordSvc.AssertExpectations(t)
			mockTokenSvc.AssertExpectations(t)
		})
	}
}
