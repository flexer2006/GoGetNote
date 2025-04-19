package jwt_service_test

import (
	"context"
	"fmt"
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
	msgEmptyUsernameInRefreshToken = "username should be empty in refresh token"
)

func TestGenerateRefreshToken(t *testing.T) {
	testLogger, err := logger.NewLogger(logger.Development, "debug")
	require.NoError(t, err, msgErrorCreatingTestLogger)

	ctx := context.Background()
	ctx = logger.NewContext(ctx, testLogger)

	t.Run("successful token generation with valid parameters", func(t *testing.T) {
		secretKey := "test-secret-key-12345"
		refreshTTL := 24 * time.Hour
		userID := "test-user-id-123"

		service := services.NewJWT(secretKey, 15*time.Minute, refreshTTL)

		token, expiryTime, err := service.GenerateRefreshToken(ctx, userID)

		require.NoError(t, err, msgNoErrorGeneratingToken)
		assert.NotEmpty(t, token, msgTokenNotEmpty)

		expectedExpiry := time.Now().Add(refreshTTL)
		assert.WithinDuration(t, expectedExpiry, expiryTime, 2*time.Second, msgExpiryTimeCorrect)

		parsedToken, err := jwt.Parse(token, func(t *jwt.Token) (interface{}, error) {
			if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("%w: %s", errInvalidSigningAlgorithm, msgInvalidSigningAlgorithm)
			}
			return []byte(secretKey), nil
		})

		require.NoError(t, err, msgTokenSignatureValid)
		assert.True(t, parsedToken.Valid, msgTokenFormatValid)

		claims, okk := parsedToken.Claims.(jwt.MapClaims)
		require.True(t, okk, msgExtractClaimsFromToken)

		assert.Equal(t, userID, claims["user_id"], msgUserIDInTokenCorrect)
		assert.Equal(t, userID, claims["sub"], msgSubjectMatchesUserID)

		username, hasUsername := claims["username"]
		if hasUsername {
			assert.Empty(t, username, msgEmptyUsernameInRefreshToken)
		}

		issuedAt, okk := claims["iat"].(float64)
		require.True(t, okk, msgIssuedAtPresentInToken)

		issuedAtTime := time.Unix(int64(issuedAt), 0)
		assert.WithinDuration(t, time.Now(), issuedAtTime, 2*time.Second, msgIssuedAtTimeCorrect)

		expiresAt, okk := claims["exp"].(float64)
		require.True(t, okk, msgExpiresAtPresentInToken)

		expiresAtTime := time.Unix(int64(expiresAt), 0)
		assert.WithinDuration(t, expiryTime, expiresAtTime, 1*time.Second, msgExpiryTimeCorrect)
	})

	t.Run("error with empty secret key", func(t *testing.T) {
		emptySecretKey := ""
		refreshTTL := 24 * time.Hour
		userID := "test-user-id-789"

		service := services.NewJWT(emptySecretKey, 15*time.Minute, refreshTTL)

		token, expiryTime, err := service.GenerateRefreshToken(ctx, userID)

		require.Error(t, err, msgErrorOnEmptySecretKey)
		require.ErrorIs(t, err, domainservices.ErrGeneratingJWTToken, msgErrorTypeCheck)
		assert.Empty(t, token, msgTokenEmptyOnError)
		assert.True(t, expiryTime.IsZero(), msgExpiryZeroOnError)
	})

	t.Run("token with expired ttl", func(t *testing.T) {
		secretKey := "test-secret-key-12345"
		refreshTTL := -24 * time.Hour
		userID := "test-user-id-expired"

		service := services.NewJWT(secretKey, 15*time.Minute, refreshTTL)

		token, expiryTime, err := service.GenerateRefreshToken(ctx, userID)

		require.NoError(t, err, msgNoErrorWithNegativeTTL)
		assert.NotEmpty(t, token, msgTokenNotEmpty)

		assert.True(t, expiryTime.Before(time.Now()), msgExpiryInPast)
	})

	t.Run("long ttl validation", func(t *testing.T) {
		secretKey := "test-secret-key-12345"
		refreshTTL := 8760 * time.Hour // roughly 1 year
		userID := "test-user-id-long"

		service := services.NewJWT(secretKey, 15*time.Minute, refreshTTL)

		token, expiryTime, err := service.GenerateRefreshToken(ctx, userID)

		require.NoError(t, err, msgNoErrorWithLongTTL)
		assert.NotEmpty(t, token, msgTokenNotEmpty)

		expectedExpiry := time.Now().Add(refreshTTL)
		assert.WithinDuration(t, expectedExpiry, expiryTime, 2*time.Second, msgExpiryTimeCorrect)
	})
}

func TestGenerateRefreshTokenWithLogger(t *testing.T) {
	testLogger, err := logger.NewLogger(logger.Development, "debug")
	require.NoError(t, err, msgErrorCreatingTestLogger)

	ctx := context.Background()
	ctx = logger.NewContext(ctx, testLogger)

	t.Run("logging token signature error", func(t *testing.T) {
		emptySecretKey := ""
		refreshTTL := 24 * time.Hour
		userID := "test-user-id-error"

		service := services.NewJWT(emptySecretKey, 15*time.Minute, refreshTTL)

		_, _, err := service.GenerateRefreshToken(ctx, userID)

		require.Error(t, err, msgErrorOnInvalidSignature)
		assert.ErrorIs(t, err, domainservices.ErrGeneratingJWTToken, msgTokenGenerationError)
	})
}
