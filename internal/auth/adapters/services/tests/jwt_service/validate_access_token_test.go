package jwt_service_test

import (
	"context"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"gogetnote/internal/auth/adapters/services"
	domainservices "gogetnote/internal/auth/domain/services"
	"gogetnote/pkg/logger"
)

//nolint:gosec
const (
	msgNoErrorValidatingToken       = "should validate token without errors"
	msgInvalidTokenFormat           = "should return invalid token error for bad format"
	msgInvalidTokenReturnedError    = "invalid token should return error"
	msgCorrectUserIDReturned        = "should return correct user ID"
	msgExpiredTokenReturnsError     = "expired token should return error"
	msgCreateTokenWithNoneAlgorithm = "should create token with none algorithm"
	msgCreateTokenWithCustomClaims  = "should create token with custom claims"
)

func TestValidateAccessToken(t *testing.T) {
	testLogger, err := logger.NewLogger(logger.Development, "debug")
	require.NoError(t, err, msgErrorCreatingTestLogger)

	ctx := context.Background()
	ctx = logger.NewContext(ctx, testLogger)

	t.Run("successful validation of a valid token", func(t *testing.T) {
		secretKey := "test-secret-key-12345"
		accessTTL := 15 * time.Minute
		userID := "test-user-id-123"
		username := "testuser"

		service := services.NewJWT(secretKey, accessTTL, 24*time.Hour)

		token, _, err := service.GenerateAccessToken(ctx, userID, username)
		require.NoError(t, err, msgNoErrorGeneratingToken)
		assert.NotEmpty(t, token, msgTokenNotEmpty)

		resultUserID, err := service.ValidateAccessToken(ctx, token)
		require.NoError(t, err, msgNoErrorValidatingToken)
		assert.Equal(t, userID, resultUserID, msgCorrectUserIDReturned)
	})

	t.Run("error on expired token", func(t *testing.T) {
		secretKey := "test-secret-key-12345"
		accessTTL := -15 * time.Minute
		userID := "test-user-id-123"
		username := "testuser"

		service := services.NewJWT(secretKey, accessTTL, 24*time.Hour)

		token, _, err := service.GenerateAccessToken(ctx, userID, username)
		require.NoError(t, err, msgNoErrorGeneratingToken)

		_, err = service.ValidateAccessToken(ctx, token)
		require.Error(t, err, msgExpiredTokenReturnsError)
		assert.ErrorIs(t, err, domainservices.ErrExpiredJWTToken, msgExpiredTokenError)
	})

	t.Run("error on invalid token format", func(t *testing.T) {
		secretKey := "test-secret-key-12345"
		service := services.NewJWT(secretKey, 15*time.Minute, 24*time.Hour)

		invalidToken := "invalid.token.format"

		_, err := service.ValidateAccessToken(ctx, invalidToken)
		require.Error(t, err, msgInvalidTokenReturnedError)
		assert.ErrorIs(t, err, domainservices.ErrInvalidJWTToken, msgInvalidTokenFormat)
	})

	t.Run("error on token with wrong signature", func(t *testing.T) {
		secretKey1 := "test-secret-key-12345"
		secretKey2 := "different-secret-key-67890"
		accessTTL := 15 * time.Minute
		userID := "test-user-id-123"
		username := "testuser"

		service1 := services.NewJWT(secretKey1, accessTTL, 24*time.Hour)
		service2 := services.NewJWT(secretKey2, accessTTL, 24*time.Hour)

		token, _, err := service1.GenerateAccessToken(ctx, userID, username)
		require.NoError(t, err, msgNoErrorGeneratingToken)

		_, err = service2.ValidateAccessToken(ctx, token)
		require.Error(t, err, msgInvalidTokenReturnedError)
		assert.ErrorIs(t, err, domainservices.ErrInvalidJWTToken, msgInvalidTokenFormat)
	})

	t.Run("error on token with invalid signing method", func(t *testing.T) {
		secretKey := "test-secret-key-12345"
		userID := "test-user-id-123"

		claims := &services.Claims{
			UserID:   userID,
			Username: "testuser",
			RegisteredClaims: jwt.RegisteredClaims{
				ExpiresAt: jwt.NewNumericDate(time.Now().Add(15 * time.Minute)),
				IssuedAt:  jwt.NewNumericDate(time.Now()),
				Subject:   userID,
			},
		}

		token := jwt.NewWithClaims(jwt.SigningMethodNone, claims)
		tokenString, err := token.SignedString(jwt.UnsafeAllowNoneSignatureType)
		require.NoError(t, err, msgCreateTokenWithNoneAlgorithm)

		service := services.NewJWT(secretKey, 15*time.Minute, 24*time.Hour)
		_, err = service.ValidateAccessToken(ctx, tokenString)
		require.Error(t, err, msgInvalidTokenReturnedError)
		assert.ErrorIs(t, err, domainservices.ErrInvalidJWTToken, msgInvalidTokenFormat)
	})

	t.Run("error on empty token", func(t *testing.T) {
		secretKey := "test-secret-key-12345"
		service := services.NewJWT(secretKey, 15*time.Minute, 24*time.Hour)

		emptyToken := ""
		_, err := service.ValidateAccessToken(ctx, emptyToken)
		require.Error(t, err, msgInvalidTokenReturnedError)
		assert.ErrorIs(t, err, domainservices.ErrInvalidJWTToken, msgInvalidTokenFormat)
	})

	t.Run("token with invalid claims", func(t *testing.T) {
		secretKey := "test-secret-key-12345"

		token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
			"some_random_field": "not_user_id",
		})

		tokenString, err := token.SignedString([]byte(secretKey))
		require.NoError(t, err, msgCreateTokenWithCustomClaims)

		service := services.NewJWT(secretKey, 15*time.Minute, 24*time.Hour)
		_, err = service.ValidateAccessToken(ctx, tokenString)
		require.Error(t, err, msgInvalidTokenReturnedError)
		assert.ErrorIs(t, err, domainservices.ErrInvalidJWTToken, msgInvalidTokenFormat)
	})
}
