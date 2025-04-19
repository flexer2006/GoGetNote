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
	ErrHashing      = errors.New("hashing error")
	ErrUserCreation = errors.New("user creation failed")
)

func TestRegister(t *testing.T) {
	testEmail := "test@example.com"
	testUsername := "testuser"
	testPassword := "password123"
	hashedPassword := "hashed_password"
	generatedUserID := "generated-user-id"

	now := time.Now()
	accessExpires := now.Add(15 * time.Minute)
	refreshExpires := now.Add(7 * 24 * time.Hour)

	accessToken := "access-token-123"
	refreshToken := "refresh-token-456"

	createdUser := &entities.User{
		ID:           generatedUserID,
		Email:        testEmail,
		Username:     testUsername,
		PasswordHash: hashedPassword,
		CreatedAt:    now,
		UpdatedAt:    now,
	}

	expectedTokenPair := &services.TokenPair{
		UserID:       generatedUserID,
		Username:     testUsername,
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		ExpiresAt:    accessExpires,
	}

	tests := []struct {
		name          string
		email         string
		username      string
		password      string
		setupMocks    func(mockUserRepo *mockUserRepository, mockTokenRepo *mockTokenRepository, mockPasswordSvc *mockPasswordService, mockTokenSvc *mockTokenService)
		expectedToken *services.TokenPair
		expectedErr   error
		errorContext  string
	}{
		{
			name:     "success - user registered successfully",
			email:    testEmail,
			username: testUsername,
			password: testPassword,
			setupMocks: func(mockUserRepo *mockUserRepository, mockTokenRepo *mockTokenRepository, mockPasswordSvc *mockPasswordService, mockTokenSvc *mockTokenService) {
				mockUserRepo.On("FindByEmail", mock.Anything, testEmail).Return(nil, entities.ErrUserNotFound).Once()

				mockPasswordSvc.On("Hash", mock.Anything, testPassword).Return(hashedPassword, nil).Once()

				mockUserRepo.On("Create", mock.Anything, mock.MatchedBy(func(u *entities.User) bool {
					return u.Email == testEmail && u.Username == testUsername && u.PasswordHash == hashedPassword
				})).Return(createdUser, nil).Once()

				mockTokenSvc.On("GenerateAccessToken", mock.Anything, generatedUserID, testUsername).
					Return(accessToken, accessExpires, nil).Once()
				mockTokenSvc.On("GenerateRefreshToken", mock.Anything, generatedUserID).
					Return(refreshToken, refreshExpires, nil).Once()

				mockTokenRepo.On("StoreRefreshToken", mock.Anything, mock.MatchedBy(func(t *services.RefreshToken) bool {
					return t.UserID == generatedUserID && t.Token == refreshToken && !t.IsRevoked
				})).Return(nil).Once()
			},
			expectedToken: expectedTokenPair,
			expectedErr:   nil,
		},
		{
			name:     "error - invalid email format",
			email:    "invalid-email",
			username: testUsername,
			password: testPassword,
			setupMocks: func(_ *mockUserRepository, _ *mockTokenRepository, _ *mockPasswordService, _ *mockTokenService) {
			},
			expectedToken: nil,
			expectedErr:   entities.ErrInvalidEmail,
			errorContext:  "validating email",
		},
		{
			name:     "Error - empty username",
			email:    testEmail,
			username: "",
			password: testPassword,
			setupMocks: func(_ *mockUserRepository, _ *mockTokenRepository, _ *mockPasswordService, _ *mockTokenService) {
			},
			expectedToken: nil,
			expectedErr:   entities.ErrEmptyUsername,
			errorContext:  "validating username",
		},
		{
			name:     "esrror - password too short",
			email:    testEmail,
			username: testUsername,
			password: "short",
			setupMocks: func(_ *mockUserRepository, _ *mockTokenRepository, _ *mockPasswordService, _ *mockTokenService) {
			},
			expectedToken: nil,
			expectedErr:   entities.ErrPasswordTooShort,
			errorContext:  "validating password",
		},
		{
			name:     "error - user already exists",
			email:    testEmail,
			username: testUsername,
			password: testPassword,
			setupMocks: func(mockUserRepo *mockUserRepository, _ *mockTokenRepository, _ *mockPasswordService, _ *mockTokenService) {
				mockUserRepo.On("FindByEmail", mock.Anything, testEmail).Return(createdUser, nil).Once()
			},
			expectedToken: nil,
			expectedErr:   services.ErrEmailAlreadyExists,
			errorContext:  "email already registered",
		},
		{
			name:     "esrror - database error during user check",
			email:    testEmail,
			username: testUsername,
			password: testPassword,
			setupMocks: func(mockUserRepo *mockUserRepository, _ *mockTokenRepository, _ *mockPasswordService, _ *mockTokenService) {
				mockUserRepo.On("FindByEmail", mock.Anything, testEmail).Return(nil, ErrDatabase).Once()
			},
			expectedToken: nil,
			expectedErr:   ErrDatabase,
			errorContext:  "checking existing user",
		},
		{
			name:     "Error - password hashing failure",
			email:    testEmail,
			username: testUsername,
			password: testPassword,
			setupMocks: func(mockUserRepo *mockUserRepository, _ *mockTokenRepository, mockPasswordSvc *mockPasswordService, _ *mockTokenService) {
				mockUserRepo.On("FindByEmail", mock.Anything, testEmail).Return(nil, entities.ErrUserNotFound).Once()

				mockPasswordSvc.On("Hash", mock.Anything, testPassword).Return("", ErrHashing).Once()
			},
			expectedToken: nil,
			expectedErr:   ErrHashing,
			errorContext:  "hashing password",
		},
		{
			name:     "error - user creation failure",
			email:    testEmail,
			username: testUsername,
			password: testPassword,
			setupMocks: func(mockUserRepo *mockUserRepository, _ *mockTokenRepository, mockPasswordSvc *mockPasswordService, _ *mockTokenService) {
				mockUserRepo.On("FindByEmail", mock.Anything, testEmail).Return(nil, entities.ErrUserNotFound).Once()

				mockPasswordSvc.On("Hash", mock.Anything, testPassword).Return(hashedPassword, nil).Once()

				mockUserRepo.On("Create", mock.Anything, mock.MatchedBy(func(u *entities.User) bool {
					return u.Email == testEmail && u.Username == testUsername && u.PasswordHash == hashedPassword
				})).Return(nil, ErrUserCreation).Once()
			},
			expectedToken: nil,
			expectedErr:   ErrUserCreation,
			errorContext:  "creating user",
		},
		{
			name:     "error - token generation failure",
			email:    testEmail,
			username: testUsername,
			password: testPassword,
			setupMocks: func(mockUserRepo *mockUserRepository, _ *mockTokenRepository, mockPasswordSvc *mockPasswordService, mockTokenSvc *mockTokenService) {
				mockUserRepo.On("FindByEmail", mock.Anything, testEmail).Return(nil, entities.ErrUserNotFound).Once()

				mockPasswordSvc.On("Hash", mock.Anything, testPassword).Return(hashedPassword, nil).Once()

				mockUserRepo.On("Create", mock.Anything, mock.MatchedBy(func(u *entities.User) bool {
					return u.Email == testEmail && u.Username == testUsername && u.PasswordHash == hashedPassword
				})).Return(createdUser, nil).Once()

				mockTokenSvc.On("GenerateAccessToken", mock.Anything, generatedUserID, testUsername).
					Return("", time.Time{}, ErrTokenGeneration).Once()
			},
			expectedToken: nil,
			expectedErr:   services.ErrTokenGenerationFailed,
			errorContext:  "generating tokens",
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
			tokenPair, err := authUseCase.Register(ctx, ttt.email, ttt.username, ttt.password)

			if ttt.expectedErr != nil {
				require.Error(t, err)
				assert.Contains(t, err.Error(), ttt.errorContext)

				if errors.Is(err, entities.ErrInvalidEmail) ||
					errors.Is(err, entities.ErrEmptyUsername) ||
					errors.Is(err, entities.ErrPasswordTooShort) ||
					errors.Is(err, services.ErrEmailAlreadyExists) ||
					errors.Is(err, services.ErrTokenGenerationFailed) {
					require.ErrorIs(t, err, ttt.expectedErr)
				}

				assert.Nil(t, tokenPair)
			} else {
				require.NoError(t, err)
				assert.NotNil(t, tokenPair)
				assert.Equal(t, ttt.expectedToken.UserID, tokenPair.UserID)
				assert.Equal(t, ttt.expectedToken.Username, tokenPair.Username)
				assert.Equal(t, ttt.expectedToken.AccessToken, tokenPair.AccessToken)
				assert.Equal(t, ttt.expectedToken.RefreshToken, tokenPair.RefreshToken)
				assert.Equal(t, ttt.expectedToken.ExpiresAt, tokenPair.ExpiresAt)
			}

			mockUserRepo.AssertExpectations(t)
			mockTokenRepo.AssertExpectations(t)
			mockPasswordSvc.AssertExpectations(t)
			mockTokenSvc.AssertExpectations(t)
		})
	}
}
