package services_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"gogetnote/internal/notes/adapters/services"
	portservices "gogetnote/internal/notes/ports/services"
	"gogetnote/pkg/logger"
)

func TestNewJWT(t *testing.T) {
	secretKey := "test-secret-key"

	service := services.NewJWT(secretKey)

	require.NotNil(t, service, "JWT service should not be nil")
}

func TestValidateAccessToken(t *testing.T) {
	ctx := context.Background()
	err := logger.InitGlobalLogger(logger.Development)
	require.NoError(t, err, "Failed to initialize logger")

	t.Run("valid token", func(t *testing.T) {
		secretKey := "test-secret-key"
		service := services.NewJWT(secretKey)
		userID := "test-user-123"

		claims := &services.Claims{
			UserID:   userID,
			Username: "testuser",
			RegisteredClaims: jwt.RegisteredClaims{
				ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
			},
		}
		token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
		tokenString, err := token.SignedString([]byte(secretKey))
		require.NoError(t, err)

		resultID, err := service.ValidateAccessToken(ctx, tokenString)

		require.NoError(t, err)
		assert.Equal(t, userID, resultID)
	})

	t.Run("expired token", func(t *testing.T) {
		secretKey := "test-secret-key"
		service := services.NewJWT(secretKey)

		claims := &services.Claims{
			UserID:   "test-user-123",
			Username: "testuser",
			RegisteredClaims: jwt.RegisteredClaims{
				ExpiresAt: jwt.NewNumericDate(time.Now().Add(-time.Hour)),
			},
		}
		token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
		tokenString, err := token.SignedString([]byte(secretKey))
		require.NoError(t, err)

		_, err = service.ValidateAccessToken(ctx, tokenString)

		require.Error(t, err)
		assert.True(t, errors.Is(err, portservices.ErrExpiredJWTToken))
	})

	t.Run("invalid token format", func(t *testing.T) {

		secretKey := "test-secret-key"
		service := services.NewJWT(secretKey)
		invalidToken := "invalid.token.format"

		_, err := service.ValidateAccessToken(ctx, invalidToken)

		require.Error(t, err)
		assert.True(t, errors.Is(err, portservices.ErrInvalidJWTToken))
	})

	t.Run("empty userID", func(t *testing.T) {
		secretKey := "test-secret-key"
		service := services.NewJWT(secretKey)

		claims := &services.Claims{
			UserID:   "",
			Username: "testuser",
			RegisteredClaims: jwt.RegisteredClaims{
				ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
			},
		}
		token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
		tokenString, err := token.SignedString([]byte(secretKey))
		require.NoError(t, err)

		_, err = service.ValidateAccessToken(ctx, tokenString)

		require.Error(t, err)
		assert.True(t, errors.Is(err, portservices.ErrInvalidJWTToken))
	})

	t.Run("different secret key", func(t *testing.T) {

		secretKey := "test-secret-key"
		differentKey := "different-secret-key"
		service := services.NewJWT(secretKey)

		claims := &services.Claims{
			UserID:   "test-user-123",
			Username: "testuser",
			RegisteredClaims: jwt.RegisteredClaims{
				ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
			},
		}
		token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
		tokenString, err := token.SignedString([]byte(differentKey))
		require.NoError(t, err)

		_, err = service.ValidateAccessToken(ctx, tokenString)

		require.Error(t, err)
		assert.True(t, errors.Is(err, portservices.ErrInvalidJWTToken))
	})

	t.Run("invalid algorithm", func(t *testing.T) {
		secretKey := "test-secret-key"
		service := services.NewJWT(secretKey)

		claims := &services.Claims{
			UserID:   "test-user-123",
			Username: "testuser",
			RegisteredClaims: jwt.RegisteredClaims{
				ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
			},
		}

		token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
		unsignedToken, err := token.SigningString()
		require.NoError(t, err)
		tokenString := unsignedToken + ".invalid-signature"

		_, err = service.ValidateAccessToken(ctx, tokenString)

		require.Error(t, err)
		assert.True(t, errors.Is(err, portservices.ErrInvalidJWTToken))
	})
}
