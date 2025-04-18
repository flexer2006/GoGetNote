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
			name:     "Success - user registered successfully",
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
			name:     "Error - invalid email format",
			email:    "invalid-email",
			username: testUsername,
			password: testPassword,
			setupMocks: func(mockUserRepo *mockUserRepository, mockTokenRepo *mockTokenRepository, mockPasswordSvc *mockPasswordService, mockTokenSvc *mockTokenService) {
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
			setupMocks: func(mockUserRepo *mockUserRepository, mockTokenRepo *mockTokenRepository, mockPasswordSvc *mockPasswordService, mockTokenSvc *mockTokenService) {
			},
			expectedToken: nil,
			expectedErr:   entities.ErrEmptyUsername,
			errorContext:  "validating username",
		},
		{
			name:     "Error - password too short",
			email:    testEmail,
			username: testUsername,
			password: "short",
			setupMocks: func(mockUserRepo *mockUserRepository, mockTokenRepo *mockTokenRepository, mockPasswordSvc *mockPasswordService, mockTokenSvc *mockTokenService) {
			},
			expectedToken: nil,
			expectedErr:   entities.ErrPasswordTooShort,
			errorContext:  "validating password",
		},
		{
			name:     "Error - user already exists",
			email:    testEmail,
			username: testUsername,
			password: testPassword,
			setupMocks: func(mockUserRepo *mockUserRepository, mockTokenRepo *mockTokenRepository, mockPasswordSvc *mockPasswordService, mockTokenSvc *mockTokenService) {
				mockUserRepo.On("FindByEmail", mock.Anything, testEmail).Return(createdUser, nil).Once()
			},
			expectedToken: nil,
			expectedErr:   services.ErrEmailAlreadyExists,
			errorContext:  "email already registered",
		},
		{
			name:     "Error - database error during user check",
			email:    testEmail,
			username: testUsername,
			password: testPassword,
			setupMocks: func(mockUserRepo *mockUserRepository, mockTokenRepo *mockTokenRepository, mockPasswordSvc *mockPasswordService, mockTokenSvc *mockTokenService) {
				mockUserRepo.On("FindByEmail", mock.Anything, testEmail).Return(nil, errors.New("database error")).Once()
			},
			expectedToken: nil,
			expectedErr:   errors.New("database error"),
			errorContext:  "checking existing user",
		},
		{
			name:     "Error - password hashing failure",
			email:    testEmail,
			username: testUsername,
			password: testPassword,
			setupMocks: func(mockUserRepo *mockUserRepository, mockTokenRepo *mockTokenRepository, mockPasswordSvc *mockPasswordService, mockTokenSvc *mockTokenService) {
				mockUserRepo.On("FindByEmail", mock.Anything, testEmail).Return(nil, entities.ErrUserNotFound).Once()

				mockPasswordSvc.On("Hash", mock.Anything, testPassword).Return("", errors.New("hashing error")).Once()
			},
			expectedToken: nil,
			expectedErr:   errors.New("hashing error"),
			errorContext:  "hashing password",
		},
		{
			name:     "Error - user creation failure",
			email:    testEmail,
			username: testUsername,
			password: testPassword,
			setupMocks: func(mockUserRepo *mockUserRepository, mockTokenRepo *mockTokenRepository, mockPasswordSvc *mockPasswordService, mockTokenSvc *mockTokenService) {
				mockUserRepo.On("FindByEmail", mock.Anything, testEmail).Return(nil, entities.ErrUserNotFound).Once()

				mockPasswordSvc.On("Hash", mock.Anything, testPassword).Return(hashedPassword, nil).Once()

				mockUserRepo.On("Create", mock.Anything, mock.MatchedBy(func(u *entities.User) bool {
					return u.Email == testEmail && u.Username == testUsername && u.PasswordHash == hashedPassword
				})).Return(nil, errors.New("user creation failed")).Once()
			},
			expectedToken: nil,
			expectedErr:   errors.New("user creation failed"),
			errorContext:  "creating user",
		},
		{
			name:     "Error - token generation failure",
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
					Return("", time.Time{}, errors.New("token generation failed")).Once()
			},
			expectedToken: nil,
			expectedErr:   services.ErrTokenGenerationFailed,
			errorContext:  "generating tokens",
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
			tokenPair, err := authUseCase.Register(ctx, tt.email, tt.username, tt.password)

			if tt.expectedErr != nil {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.errorContext)

				if errors.Is(err, entities.ErrInvalidEmail) ||
					errors.Is(err, entities.ErrEmptyUsername) ||
					errors.Is(err, entities.ErrPasswordTooShort) ||
					errors.Is(err, services.ErrEmailAlreadyExists) ||
					errors.Is(err, services.ErrTokenGenerationFailed) {
					assert.ErrorIs(t, err, tt.expectedErr)
				}

				assert.Nil(t, tokenPair)
			} else {
				require.NoError(t, err)
				assert.NotNil(t, tokenPair)
				assert.Equal(t, tt.expectedToken.UserID, tokenPair.UserID)
				assert.Equal(t, tt.expectedToken.Username, tokenPair.Username)
				assert.Equal(t, tt.expectedToken.AccessToken, tokenPair.AccessToken)
				assert.Equal(t, tt.expectedToken.RefreshToken, tokenPair.RefreshToken)
				assert.Equal(t, tt.expectedToken.ExpiresAt, tokenPair.ExpiresAt)
			}

			mockUserRepo.AssertExpectations(t)
			mockTokenRepo.AssertExpectations(t)
			mockPasswordSvc.AssertExpectations(t)
			mockTokenSvc.AssertExpectations(t)
		})
	}
}
