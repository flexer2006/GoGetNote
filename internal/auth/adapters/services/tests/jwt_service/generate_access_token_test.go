package jwt_service_test

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"gogetnote/internal/auth/adapters/services"
	domain "gogetnote/internal/auth/domain/services"
	"gogetnote/pkg/logger"
)

var errInvalidSigningAlgorithm = errors.New("invalid signing algorithm")

//nolint:gosec
const (
	msgTokenFormatValid         = "token should have valid JWT format"
	msgTokenSignatureValid      = "token signature should be valid"
	msgExpiryTimeCorrect        = "token expiration time should match expected"
	msgErrorOnEmptySecretKey    = "should return error with empty secret key"
	msgErrorTypeCheck           = "error type should match expected"
	msgUserIDInTokenCorrect     = "user ID in token should match provided value"
	msgUsernameInTokenCorrect   = "username in token should match provided value"
	msgIssuedAtTimeCorrect      = "token issued at time should be approximately current"
	msgSubjectMatchesUserID     = "token subject should match user ID"
	msgNoErrorGeneratingToken   = "should not return errors when generating token"
	msgTokenNotEmpty            = "token should not be empty"
	msgNoErrorWithEmptyUsername = "should not return errors when generating token with empty username"
	msgTokenEmptyOnError        = "token should be empty on error"
	msgExpiryZeroOnError        = "expiration time should be zero on error"
	msgNoErrorWithNegativeTTL   = "should generate token even with negative TTL"
	msgExpiryInPast             = "expiration time should be in the past"
	msgErrorOnExpiredToken      = "should return error when validating expired token"
	msgExpiredTokenError        = "should return expired token error"
	msgNoErrorWithLongTTL       = "should not return errors when generating token with long TTL"
	msgErrorOnInvalidSignature  = "should return error with invalid signature"
	msgTokenGenerationError     = "should return token generation error"
	msgErrorCreatingTestLogger  = "error creating test logger"
	msgExtractClaimsFromToken   = "should be able to extract claims from token"
	msgExpiresAtPresentInToken  = "expires at should be present in token"
	msgIssuedAtPresentInToken   = "issued at should be present in token"
	msgInvalidSigningAlgorithm  = "invalid signing algorithm"
)

func TestGenerateAccessToken(t *testing.T) {
	testLogger, err := logger.NewLogger(logger.Development, "debug")
	require.NoError(t, err, msgErrorCreatingTestLogger)

	ctx := context.Background()
	ctx = logger.NewContext(ctx, testLogger)

	t.Run("successful token generation with valid parameters", func(t *testing.T) {
		secretKey := "test-secret-key-12345"
		accessTTL := 15 * time.Minute
		userID := "test-user-id-123"
		username := "testuser"

		service := services.NewJWT(secretKey, accessTTL, 24*time.Hour)

		token, expiryTime, err := service.GenerateAccessToken(ctx, userID, username)

		require.NoError(t, err, msgNoErrorGeneratingToken)
		assert.NotEmpty(t, token, msgTokenNotEmpty)

		expectedExpiry := time.Now().Add(accessTTL)
		assert.WithinDuration(t, expectedExpiry, expiryTime, 2*time.Second, msgExpiryTimeCorrect)

		parsedToken, err := jwt.Parse(token, func(token *jwt.Token) (interface{}, error) {
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("%w: %s", errInvalidSigningAlgorithm, msgInvalidSigningAlgorithm)
			}
			return []byte(secretKey), nil
		})

		require.NoError(t, err, msgTokenSignatureValid)
		assert.True(t, parsedToken.Valid, msgTokenFormatValid)

		claims, okk := parsedToken.Claims.(jwt.MapClaims)
		require.True(t, okk, msgExtractClaimsFromToken)

		assert.Equal(t, userID, claims["user_id"], msgUserIDInTokenCorrect)
		assert.Equal(t, username, claims["username"], msgUsernameInTokenCorrect)
		assert.Equal(t, userID, claims["sub"], msgSubjectMatchesUserID)

		issuedAt, okk := claims["iat"].(float64)
		require.True(t, okk, msgIssuedAtPresentInToken)

		issuedAtTime := time.Unix(int64(issuedAt), 0)
		assert.WithinDuration(t, time.Now(), issuedAtTime, 2*time.Second, msgIssuedAtTimeCorrect)

		expiresAt, okk := claims["exp"].(float64)
		require.True(t, okk, msgExpiresAtPresentInToken)

		expiresAtTime := time.Unix(int64(expiresAt), 0)
		assert.WithinDuration(t, expiryTime, expiresAtTime, 1*time.Second, msgExpiryTimeCorrect)
	})

	t.Run("token generation with empty username", func(t *testing.T) {
		secretKey := "test-secret-key-12345"
		accessTTL := 15 * time.Minute
		userID := "test-user-id-456"
		username := ""

		service := services.NewJWT(secretKey, accessTTL, 24*time.Hour)

		token, expiryTime, err := service.GenerateAccessToken(ctx, userID, username)

		require.NoError(t, err, msgNoErrorWithEmptyUsername)
		assert.NotEmpty(t, token, msgTokenNotEmpty)

		parsedToken, err := jwt.Parse(token, func(_ *jwt.Token) (interface{}, error) {
			return []byte(secretKey), nil
		})

		require.NoError(t, err, msgTokenSignatureValid)

		claims, ok := parsedToken.Claims.(jwt.MapClaims)
		require.True(t, ok, msgExtractClaimsFromToken)

		assert.Equal(t, userID, claims["user_id"], msgUserIDInTokenCorrect)
		assert.Equal(t, username, claims["username"], msgUsernameInTokenCorrect)

		expectedExpiry := time.Now().Add(accessTTL)
		assert.WithinDuration(t, expectedExpiry, expiryTime, 2*time.Second, msgExpiryTimeCorrect)
	})

	t.Run("error with empty secret key", func(t *testing.T) {
		emptySecretKey := ""
		accessTTL := 15 * time.Minute
		userID := "test-user-id-789"
		username := "testuser"

		service := services.NewJWT(emptySecretKey, accessTTL, 24*time.Hour)

		token, expiryTime, err := service.GenerateAccessToken(ctx, userID, username)

		require.Error(t, err, msgErrorOnEmptySecretKey)
		require.ErrorIs(t, err, domain.ErrGeneratingJWTToken, msgErrorTypeCheck)
		assert.Empty(t, token, msgTokenEmptyOnError)
		assert.True(t, expiryTime.IsZero(), msgExpiryZeroOnError)
	})

	t.Run("token with expired ttl", func(t *testing.T) {
		secretKey := "test-secret-key-12345"
		accessTTL := -15 * time.Minute
		userID := "test-user-id-expired"
		username := "expireduser"

		service := services.NewJWT(secretKey, accessTTL, 24*time.Hour)

		token, expiryTime, err := service.GenerateAccessToken(ctx, userID, username)

		require.NoError(t, err, msgNoErrorWithNegativeTTL)
		assert.NotEmpty(t, token, msgTokenNotEmpty)

		assert.True(t, expiryTime.Before(time.Now()), msgExpiryInPast)

		_, err = service.ValidateAccessToken(ctx, token)
		require.Error(t, err, msgErrorOnExpiredToken)
		assert.ErrorIs(t, err, domain.ErrExpiredJWTToken, msgExpiredTokenError)
	})

	t.Run("long ttl validation", func(t *testing.T) {
		secretKey := "test-secret-key-12345"
		accessTTL := 8760 * time.Hour
		userID := "test-user-id-long"
		username := "longuser"

		service := services.NewJWT(secretKey, accessTTL, 24*time.Hour)

		token, expiryTime, err := service.GenerateAccessToken(ctx, userID, username)

		require.NoError(t, err, msgNoErrorWithLongTTL)
		assert.NotEmpty(t, token, msgTokenNotEmpty)

		expectedExpiry := time.Now().Add(accessTTL)
		assert.WithinDuration(t, expectedExpiry, expiryTime, 2*time.Second, msgExpiryTimeCorrect)
	})
}

func TestGenerateAccessTokenWithLogger(t *testing.T) {
	testLogger, err := logger.NewLogger(logger.Development, "debug")
	require.NoError(t, err, msgErrorCreatingTestLogger)

	ctx := context.Background()
	ctx = logger.NewContext(ctx, testLogger)

	t.Run("logging token signature error", func(t *testing.T) {
		emptySecretKey := ""
		accessTTL := 15 * time.Minute
		userID := "test-user-id-error"
		username := "erroruser"

		service := services.NewJWT(emptySecretKey, accessTTL, 24*time.Hour)

		_, _, err := service.GenerateAccessToken(ctx, userID, username)

		require.Error(t, err, msgErrorOnInvalidSignature)
		assert.ErrorIs(t, err, domain.ErrGeneratingJWTToken, msgTokenGenerationError)
	})
}
