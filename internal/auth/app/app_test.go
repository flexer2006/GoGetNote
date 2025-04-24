package app_test

import (
	"context"
	"errors"
	"fmt"
	"gogetnote/internal/auth/app"
	"gogetnote/internal/auth/domain/entities"
	"gogetnote/internal/auth/domain/services"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
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

var (
	errTokenNotFound = errors.New("token not found")
	errDatabase      = errors.New("database error")
)

func TestLogout(t *testing.T) {
	const (
		userID       = "user-123"
		refreshToken = "refresh-token-123"
	)

	now := time.Now()
	refreshExpiry := now.Add(7 * 24 * time.Hour)

	testTokenObj := &services.RefreshToken{
		ID:        "token-id-123",
		UserID:    userID,
		Token:     refreshToken,
		ExpiresAt: refreshExpiry,
		CreatedAt: now.Add(-24 * time.Hour),
		IsRevoked: false,
	}

	tests := []struct {
		name         string
		refreshToken string
		setupMocks   func(mockUserRepo *mockUserRepository, mockTokenRepo *mockTokenRepository, mockPasswordSvc *mockPasswordService, mockTokenSvc *mockTokenService)
		expectedErr  error
		errorContext string
	}{
		{
			name:         "success - token revoked successfully",
			refreshToken: refreshToken,
			setupMocks: func(_ *mockUserRepository, mockTokenRepo *mockTokenRepository, _ *mockPasswordService, _ *mockTokenService) {
				mockTokenRepo.On("FindByToken", mock.Anything, refreshToken).Return(testTokenObj, nil).Once()
				mockTokenRepo.On("RevokeToken", mock.Anything, refreshToken).Return(nil).Once()
			},
			expectedErr: nil,
		},
		{
			name:         "error - token not found but still tries to revoke",
			refreshToken: "non-existent-token",
			setupMocks: func(_ *mockUserRepository, mockTokenRepo *mockTokenRepository, _ *mockPasswordService, _ *mockTokenService) {
				mockTokenRepo.On("FindByToken", mock.Anything, "non-existent-token").Return(nil, errTokenNotFound).Once()
				mockTokenRepo.On("RevokeToken", mock.Anything, "non-existent-token").Return(nil).Once()
			},
			expectedErr: nil,
		},
		{
			name:         "error - cannot revoke token",
			refreshToken: refreshToken,
			setupMocks: func(_ *mockUserRepository, mockTokenRepo *mockTokenRepository, _ *mockPasswordService, _ *mockTokenService) {
				mockTokenRepo.On("FindByToken", mock.Anything, refreshToken).Return(testTokenObj, nil).Once()
				mockTokenRepo.On("RevokeToken", mock.Anything, refreshToken).Return(errDatabase).Once()
			},
			expectedErr:  errDatabase,
			errorContext: "revoking token",
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
			err := authUseCase.Logout(ctx, ttt.refreshToken)

			if ttt.expectedErr != nil {
				require.Error(t, err)
				assert.Contains(t, err.Error(), ttt.errorContext)
			} else {
				require.NoError(t, err)
			}

			mockUserRepo.AssertExpectations(t)
			mockTokenRepo.AssertExpectations(t)
			mockPasswordSvc.AssertExpectations(t)
			mockTokenSvc.AssertExpectations(t)
		})
	}
}

const (
	ErrCreateUser      = "failed to create user"
	ErrFindUserByID    = "failed to find user by ID"
	ErrFindUserByEmail = "failed to find user by email"
	ErrUserEmailLookup = "error while finding user by email"
	ErrUpdateUser      = "failed to update user"
	ErrUpdateUserProc  = "error while updating user"
	ErrDeleteUser      = "error when deleting user"
)

// nolint:gosec
const (
	ErrStoreRefreshToken   = "error when storing refresh token"
	ErrFindToken           = "error when searching for token"
	ErrGetToken            = "error when retrieving token"
	ErrRevokeToken         = "error when revoking token"
	ErrRevokeAllUserTokens = "error when revoking all user tokens"
	ErrCleanupTokens       = "error when cleaning up expired tokens"
	ErrFindUserTokens      = "error when searching for user tokens"
	ErrGetUserTokens       = "error when retrieving user tokens"
)

type mockUserRepository struct {
	mock.Mock
}

func (m *mockUserRepository) Create(ctx context.Context, user *entities.User) (*entities.User, error) {
	args := m.Called(ctx, user)
	if args.Get(0) == nil {
		err := args.Error(1)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", ErrCreateUser, err)
		}
		return nil, nil
	}
	return args.Get(0).(*entities.User), nil
}

func (m *mockUserRepository) FindByID(ctx context.Context, id string) (*entities.User, error) {
	args := m.Called(ctx, id)
	if args.Get(0) == nil {
		err := args.Error(1)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", ErrFindUserByID, err)
		}
		return nil, nil
	}
	return args.Get(0).(*entities.User), nil
}

func (m *mockUserRepository) FindByEmail(ctx context.Context, email string) (*entities.User, error) {
	args := m.Called(ctx, email)
	if args.Get(0) == nil {
		err := args.Error(1)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", ErrFindUserByEmail, err)
		}
		return nil, nil
	}

	user := args.Get(0).(*entities.User)
	err := args.Error(1)
	if err != nil {
		return user, fmt.Errorf("%s: %w", ErrUserEmailLookup, err)
	}
	return user, nil
}

func (m *mockUserRepository) Update(ctx context.Context, user *entities.User) (*entities.User, error) {
	args := m.Called(ctx, user)
	if args.Get(0) == nil {
		err := args.Error(1)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", ErrUpdateUser, err)
		}
		return nil, nil
	}

	updatedUser := args.Get(0).(*entities.User)
	err := args.Error(1)
	if err != nil {
		return updatedUser, fmt.Errorf("%s: %w", ErrUpdateUserProc, err)
	}
	return updatedUser, nil
}

func (m *mockUserRepository) Delete(ctx context.Context, id string) error {
	args := m.Called(ctx, id)
	if err := args.Error(0); err != nil {
		return fmt.Errorf("%s: %w", ErrDeleteUser, err)
	}
	return nil
}

type mockTokenRepository struct {
	mock.Mock
}

func (m *mockTokenRepository) StoreRefreshToken(ctx context.Context, token *services.RefreshToken) error {
	err := m.Called(ctx, token).Error(0)
	if err != nil {
		return fmt.Errorf("%s: %w", ErrStoreRefreshToken, err)
	}
	return nil
}

func (m *mockTokenRepository) FindByToken(ctx context.Context, token string) (*services.RefreshToken, error) {
	args := m.Called(ctx, token)
	if args.Get(0) == nil {
		err := args.Error(1)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", ErrFindToken, err)
		}
		return nil, nil
	}
	err := args.Error(1)
	if err != nil {
		return args.Get(0).(*services.RefreshToken), fmt.Errorf("%s: %w", ErrGetToken, err)
	}
	return args.Get(0).(*services.RefreshToken), nil
}

func (m *mockTokenRepository) RevokeToken(ctx context.Context, token string) error {
	err := m.Called(ctx, token).Error(0)
	if err != nil {
		return fmt.Errorf("%s: %w", ErrRevokeToken, err)
	}
	return nil
}

func (m *mockTokenRepository) RevokeAllUserTokens(ctx context.Context, userID string) error {
	err := m.Called(ctx, userID).Error(0)
	if err != nil {
		return fmt.Errorf("%s: %w", ErrRevokeAllUserTokens, err)
	}
	return nil
}

func (m *mockTokenRepository) CleanupExpiredTokens(ctx context.Context) error {
	err := m.Called(ctx).Error(0)
	if err != nil {
		return fmt.Errorf("%s: %w", ErrCleanupTokens, err)
	}
	return nil
}

func (m *mockTokenRepository) FindUserTokens(ctx context.Context, userID string) ([]*services.RefreshToken, error) {
	args := m.Called(ctx, userID)
	if args.Get(0) == nil {
		err := args.Error(1)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", ErrFindUserTokens, err)
		}
		return nil, nil
	}
	err := args.Error(1)
	if err != nil {
		return args.Get(0).([]*services.RefreshToken), fmt.Errorf("%s: %w", ErrGetUserTokens, err)
	}
	return args.Get(0).([]*services.RefreshToken), nil
}

type mockPasswordService struct {
	mock.Mock
}

func (m *mockPasswordService) Hash(ctx context.Context, password string) (string, error) {
	args := m.Called(ctx, password)
	return args.String(0), args.Error(1)
}

func (m *mockPasswordService) Verify(ctx context.Context, password, hash string) (bool, error) {
	args := m.Called(ctx, password, hash)
	return args.Bool(0), args.Error(1)
}

type mockTokenService struct {
	mock.Mock
}

func (m *mockTokenService) GenerateAccessToken(ctx context.Context, userID, username string) (string, time.Time, error) {
	args := m.Called(ctx, userID, username)
	return args.String(0), args.Get(1).(time.Time), args.Error(2)
}

func (m *mockTokenService) GenerateRefreshToken(ctx context.Context, userID string) (string, time.Time, error) {
	args := m.Called(ctx, userID)
	return args.String(0), args.Get(1).(time.Time), args.Error(2)
}

func (m *mockTokenService) ValidateAccessToken(ctx context.Context, token string) (string, error) {
	args := m.Called(ctx, token)
	return args.String(0), args.Error(1)
}

func TestNewAuthUseCase(t *testing.T) {
	mockUserRepo := new(mockUserRepository)
	mockTokenRepo := new(mockTokenRepository)
	mockPasswordSvc := new(mockPasswordService)
	mockTokenSvc := new(mockTokenService)

	useCase := app.NewAuthUseCase(mockUserRepo, mockTokenRepo, mockPasswordSvc, mockTokenSvc)

	assert.NotNil(t, useCase)
}

var (
	ErrTokenNotFound         = errors.New("token not found")
	ErrDatabase              = errors.New("database error")
	ErrTokenGenerationFailed = errors.New("token generation failed")
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
			name:         "success - token refreshed successfully",
			refreshToken: refreshToken,
			setupMocks: func(mockUserRepo *mockUserRepository, mockTokenRepo *mockTokenRepository, _ *mockPasswordService, mockTokenSvc *mockTokenService) {
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
			name:         "error - invalid refresh token",
			refreshToken: "invalid-token",
			setupMocks: func(_ *mockUserRepository, mockTokenRepo *mockTokenRepository, _ *mockPasswordService, _ *mockTokenService) {
				mockTokenRepo.On("FindByToken", mock.Anything, "invalid-token").
					Return(nil, ErrTokenNotFound).Once()
			},
			expectedPair: nil,
			expectedErr:  services.ErrInvalidRefreshToken,
			errorContext: "finding refresh token",
		},
		{
			name:         "error - revoked refresh token",
			refreshToken: "revoked-token-123",
			setupMocks: func(_ *mockUserRepository, mockTokenRepo *mockTokenRepository, _ *mockPasswordService, _ *mockTokenService) {
				mockTokenRepo.On("FindByToken", mock.Anything, "revoked-token-123").
					Return(revokedTokenObj, nil).Once()
			},
			expectedPair: nil,
			expectedErr:  services.ErrRevokedRefreshToken,
			errorContext: "token revoked",
		},
		{
			name:         "error - user not found",
			refreshToken: refreshToken,
			setupMocks: func(mockUserRepo *mockUserRepository, mockTokenRepo *mockTokenRepository, _ *mockPasswordService, _ *mockTokenService) {
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
			name:         "error - cannot revoke old token",
			refreshToken: refreshToken,
			setupMocks: func(mockUserRepo *mockUserRepository, mockTokenRepo *mockTokenRepository, _ *mockPasswordService, _ *mockTokenService) {
				mockTokenRepo.On("FindByToken", mock.Anything, refreshToken).
					Return(testTokenObj, nil).Once()
				mockUserRepo.On("FindByID", mock.Anything, userID).
					Return(testUser, nil).Once()
				mockTokenRepo.On("RevokeToken", mock.Anything, refreshToken).
					Return(ErrDatabase).Once()
			},
			expectedPair: nil,
			expectedErr:  ErrDatabase,
			errorContext: "revoking old token",
		},
		{
			name:         "error - cannot generate new tokens",
			refreshToken: refreshToken,
			setupMocks: func(mockUserRepo *mockUserRepository, mockTokenRepo *mockTokenRepository, _ *mockPasswordService, mockTokenSvc *mockTokenService) {
				mockTokenRepo.On("FindByToken", mock.Anything, refreshToken).
					Return(testTokenObj, nil).Once()
				mockUserRepo.On("FindByID", mock.Anything, userID).
					Return(testUser, nil).Once()
				mockTokenRepo.On("RevokeToken", mock.Anything, refreshToken).
					Return(nil).Once()
				mockTokenSvc.On("GenerateAccessToken", mock.Anything, userID, username).
					Return("", time.Time{}, ErrTokenGenerationFailed).Once()
			},
			expectedPair: nil,
			expectedErr:  services.ErrTokenGenerationFailed,
			errorContext: "generating new tokens",
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
			tokenPair, err := authUseCase.RefreshTokens(ctx, ttt.refreshToken)

			if ttt.expectedErr != nil {
				require.Error(t, err)
				assert.Contains(t, err.Error(), ttt.errorContext)

				if errors.Is(err, services.ErrInvalidRefreshToken) ||
					errors.Is(err, services.ErrRevokedRefreshToken) ||
					errors.Is(err, entities.ErrUserNotFound) ||
					errors.Is(err, services.ErrTokenGenerationFailed) {
					require.ErrorIs(t, err, ttt.expectedErr)
				}

				assert.Nil(t, tokenPair)
			} else {
				require.NoError(t, err)
				assert.NotNil(t, tokenPair)
				assert.Equal(t, ttt.expectedPair.UserID, tokenPair.UserID)
				assert.Equal(t, ttt.expectedPair.Username, tokenPair.Username)
				assert.Equal(t, ttt.expectedPair.AccessToken, tokenPair.AccessToken)
				assert.Equal(t, ttt.expectedPair.RefreshToken, tokenPair.RefreshToken)
				assert.Equal(t, ttt.expectedPair.ExpiresAt, tokenPair.ExpiresAt)
			}

			mockUserRepo.AssertExpectations(t)
			mockTokenRepo.AssertExpectations(t)
			mockPasswordSvc.AssertExpectations(t)
			mockTokenSvc.AssertExpectations(t)
		})
	}
}

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

func TestValidateEmail(t *testing.T) {
	validateEmail := app.GetValidateEmailFunc()

	tests := []struct {
		name    string
		email   string
		wantErr error
	}{
		{
			name:    "valid standard email",
			email:   "test@example.com",
			wantErr: nil,
		},
		{
			name:    "valid email with numbers",
			email:   "user123@example.com",
			wantErr: nil,
		},
		{
			name:    "valid email with dot in local part",
			email:   "first.last@example.com",
			wantErr: nil,
		},
		{
			name:    "valid email with plus",
			email:   "user+tag@example.com",
			wantErr: nil,
		},
		{
			name:    "valid email with subdomain",
			email:   "user@sub.example.com",
			wantErr: nil,
		},
		{
			name:    "empty email",
			email:   "",
			wantErr: entities.ErrInvalidEmail,
		},
		{
			name:    "email without @",
			email:   "userexample.com",
			wantErr: entities.ErrInvalidEmail,
		},
		{
			name:    "email without domain",
			email:   "user@",
			wantErr: entities.ErrInvalidEmail,
		},
		{
			name:    "email without local part",
			email:   "@example.com",
			wantErr: entities.ErrInvalidEmail,
		},
		{
			name:    "email with invalid characters",
			email:   "user*name@example.com",
			wantErr: entities.ErrInvalidEmail,
		},
		{
			name:    "email with too short domain",
			email:   "user@e.c",
			wantErr: entities.ErrInvalidEmail,
		},
		{
			name:    "email with spaces",
			email:   "user name@example.com",
			wantErr: entities.ErrInvalidEmail,
		},
	}

	for _, ttt := range tests {
		t.Run(ttt.name, func(t *testing.T) {
			err := validateEmail(ttt.email)

			if ttt.wantErr == nil {
				assert.NoError(t, err)
			} else {
				assert.ErrorIs(t, err, ttt.wantErr)
			}
		})
	}
}

func TestValidatePassword(t *testing.T) {
	validatePassword := app.GetValidatePasswordFunc()

	tests := []struct {
		name     string
		password string
		wantErr  error
	}{
		{
			name:     "valid password with letters and digits",
			password: "password123",
			wantErr:  nil,
		},
		{
			name:     "valid complex password",
			password: "P@ssw0rd!123",
			wantErr:  nil,
		},
		{
			name:     "password too short",
			password: "pass12",
			wantErr:  entities.ErrPasswordTooShort,
		},
		{
			name:     "password without letters",
			password: "12345678",
			wantErr:  entities.ErrPasswordTooWeak,
		},
		{
			name:     "password without digits",
			password: "passwordonly",
			wantErr:  entities.ErrPasswordTooWeak,
		},
		{
			name:     "empty password",
			password: "",
			wantErr:  entities.ErrPasswordTooShort,
		},
	}

	for _, ttt := range tests {
		t.Run(ttt.name, func(t *testing.T) {
			err := validatePassword(ttt.password)

			if ttt.wantErr == nil {
				assert.NoError(t, err)
			} else {
				assert.ErrorIs(t, err, ttt.wantErr)
			}
		})
	}
}

const (
	ErrCreatingUser       = "error creating user"
	ErrFindingUserByID    = "error finding user by ID"
	ErrFindingUserByEmail = "error finding user by email"
	ErrUpdatingUser       = "error updating user"
	ErrDeletingUser       = "error deleting user"
)

func TestGetUserProfile(t *testing.T) {
	mockRepo := new(mockUserRepository)
	useCase := app.NewUserUseCase(mockRepo)
	ctx := context.Background()

	testUser := &entities.User{
		ID:           "test-user-id",
		Email:        "test@example.com",
		Username:     "testuser",
		PasswordHash: "hashed_password",
		CreatedAt:    time.Now(),
		UpdatedAt:    time.Now(),
	}

	tests := []struct {
		name           string
		userID         string
		mockSetup      func()
		expectedUser   *entities.User
		expectedErrMsg string
		expectedErr    error
	}{
		{
			name:   "success case - user found",
			userID: "test-user-id",
			mockSetup: func() {
				mockRepo.On("FindByID", mock.Anything, "test-user-id").Return(testUser, nil).Once()
			},
			expectedUser: testUser,
			expectedErr:  nil,
		},
		{
			name:   "error case - empty user ID",
			userID: "",
			mockSetup: func() {
			},
			expectedUser:   nil,
			expectedErrMsg: "validating user ID",
			expectedErr:    entities.ErrEmptyUserID,
		},
		{
			name:   "error case - user not found",
			userID: "nonexistent-user-id",
			mockSetup: func() {
				mockRepo.On("FindByID", mock.Anything, "nonexistent-user-id").Return(nil, entities.ErrUserNotFound).Once()
			},
			expectedUser:   nil,
			expectedErrMsg: "fetching user profile",
			expectedErr:    entities.ErrUserNotFound,
		},
		{
			name:   "error case - repository error",
			userID: "error-user-id",
			mockSetup: func() {
				mockRepo.On("FindByID", mock.Anything, "error-user-id").Return(nil, ErrDatabaseConnection).Once()
			},
			expectedUser:   nil,
			expectedErrMsg: "fetching user profile",
			expectedErr:    ErrDatabaseConnection,
		},
	}

	for _, ttt := range tests {
		t.Run(ttt.name, func(t *testing.T) {
			ttt.mockSetup()

			user, err := useCase.GetUserProfile(ctx, ttt.userID)

			if ttt.expectedErr != nil {
				require.Error(t, err)
				assert.Contains(t, err.Error(), ttt.expectedErrMsg)

				if errors.Is(err, entities.ErrEmptyUserID) || errors.Is(err, entities.ErrUserNotFound) {
					require.ErrorIs(t, err, ttt.expectedErr)
				}
				assert.Nil(t, user)
			} else {
				require.NoError(t, err)
				assert.Equal(t, ttt.expectedUser, user)
			}

			mockRepo.AssertExpectations(t)
		})
	}
}

const msgReturnNonNilObject = "NewUserUseCase should return a non-nil object"

func TestNewUserUseCase(t *testing.T) {
	mockRepo := new(mockUserRepository)

	useCase := app.NewUserUseCase(mockRepo)

	assert.NotNil(t, useCase, msgReturnNonNilObject)
}
