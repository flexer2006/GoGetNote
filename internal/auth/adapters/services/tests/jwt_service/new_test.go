package jwt_service_test

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"gogetnote/internal/auth/adapters/services"
	svc "gogetnote/internal/auth/ports/services"
	"gogetnote/pkg/logger"
)

const (
	msgGenerateAccessTokenNoError  = "should generate access token without errors"
	msgAccessTokenNotEmpty         = "access token should not be empty"
	msgAccessTokenExpiry           = "access token expiry should be approximately current time + accessTTL"
	msgGenerateRefreshTokenNoError = "should generate refresh token without errors"
	msgRefreshTokenNotEmpty        = "refresh token should not be empty"
	msgRefreshTokenExpiry          = "refresh token expiry should be approximately current time + refreshTTL"
	msgValidAccessTokenNoError     = "valid access token should not cause error"
	msgUserIDMatch                 = "user ID should match the original"
)

func TestNew(t *testing.T) {
	testCases := []struct {
		name            string
		secretKey       string
		accessTokenTTL  time.Duration
		refreshTokenTTL time.Duration
	}{
		{
			name:            "with basic settings",
			secretKey:       "test-secret-key",
			accessTokenTTL:  15 * time.Minute,
			refreshTokenTTL: 24 * time.Hour,
		},
		{
			name:            "with empty key and zero TTL",
			secretKey:       "",
			accessTokenTTL:  0,
			refreshTokenTTL: 0,
		},
		{
			name:            "with very long key and large TTL",
			secretKey:       "very-long-secret-key-for-testing-purposes-123456789012345678901234567890",
			accessTokenTTL:  720 * time.Hour,
			refreshTokenTTL: 8760 * time.Hour,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			service := services.NewJWT(tc.secretKey, tc.accessTokenTTL, tc.refreshTokenTTL)

			assert.Implements(t, (*svc.TokenService)(nil), service)
		})
	}
}

func TestNewServiceFunctionality(t *testing.T) {
	testLogger, err := logger.NewLogger(logger.Development, "debug")
	require.NoError(t, err, "error creating test logger")

	ctx := context.Background()
	ctx = logger.NewContext(ctx, testLogger)
	// #nosec G101
	secretKey := "test-jwt_service-key"
	accessTTL := 15 * time.Minute
	refreshTTL := 24 * time.Hour
	userID := "test-user-123"
	username := "testuser"

	service := services.NewJWT(secretKey, accessTTL, refreshTTL)

	accessToken, accessExpiry, err := service.GenerateAccessToken(ctx, userID, username)
	require.NoError(t, err, msgGenerateAccessTokenNoError)
	assert.NotEmpty(t, accessToken, msgAccessTokenNotEmpty)

	expectedAccessExpiry := time.Now().Add(accessTTL)
	assert.WithinDuration(t, expectedAccessExpiry, accessExpiry, 2*time.Second, msgAccessTokenExpiry)

	refreshToken, refreshExpiry, err := service.GenerateRefreshToken(ctx, userID)
	require.NoError(t, err, msgGenerateRefreshTokenNoError)
	assert.NotEmpty(t, refreshToken, msgRefreshTokenNotEmpty)

	expectedRefreshExpiry := time.Now().Add(refreshTTL)
	assert.WithinDuration(t, expectedRefreshExpiry, refreshExpiry, 2*time.Second, msgRefreshTokenExpiry)

	validatedUserID, err := service.ValidateAccessToken(ctx, accessToken)
	require.NoError(t, err, msgValidAccessTokenNoError)
	assert.Equal(t, userID, validatedUserID, msgUserIDMatch)
}
