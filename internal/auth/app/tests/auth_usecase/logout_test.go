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
	"gogetnote/internal/auth/domain/services"
)

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
