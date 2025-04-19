package service_factory_test

import (
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"testing"

	"gogetnote/internal/auth/adapters/services"
)

const (
	msgTokenServiceShouldNotBeNil = "token service should not be nil"
	msgShouldBeCorrectType        = "returned service should be of correct type"
	msgShouldReturnSameInstance   = "should return the same service instance on multiple calls"
	msgShouldNotBeNilWithEmptyKey = "token service should not be nil even with empty key"
	msgShouldNotBeNilWithZeroTTL  = "token service should not be nil even with zero TTL"
)

func TestServiceFactory_TokenService(t *testing.T) {
	t.Run("returns non-nil token service", func(t *testing.T) {
		factory := services.NewServiceFactory(
			defaultJWTSecretKey,
			defaultAccessTokenTTL,
			defaultRefreshTokenTTL,
			defaultBcryptCost,
		)

		tokenService := factory.TokenService()

		require.NotNil(t, tokenService, msgTokenServiceShouldNotBeNil)
		assert.IsType(t, &services.ServiceJWT{}, tokenService, msgShouldBeCorrectType)
	})

	t.Run("returns same instance on multiple calls", func(t *testing.T) {
		factory := services.NewServiceFactory(
			defaultJWTSecretKey,
			defaultAccessTokenTTL,
			defaultRefreshTokenTTL,
			defaultBcryptCost,
		)

		service1 := factory.TokenService()
		service2 := factory.TokenService()

		assert.Same(t, service1, service2, msgShouldReturnSameInstance)
	})

	t.Run("with empty secret key", func(t *testing.T) {
		factory := services.NewServiceFactory(
			"", // empty secret key
			defaultAccessTokenTTL,
			defaultRefreshTokenTTL,
			defaultBcryptCost,
		)

		tokenService := factory.TokenService()

		require.NotNil(t, tokenService, msgShouldNotBeNilWithEmptyKey)
		assert.IsType(t, &services.ServiceJWT{}, tokenService, msgShouldBeCorrectType)
	})

	t.Run("with zero token ttl", func(t *testing.T) {
		factory := services.NewServiceFactory(
			defaultJWTSecretKey,
			0, // zero TTL for access token
			0, // zero TTL for refresh token
			defaultBcryptCost,
		)

		tokenService := factory.TokenService()

		require.NotNil(t, tokenService, msgShouldNotBeNilWithZeroTTL)
		assert.IsType(t, &services.ServiceJWT{}, tokenService, msgShouldBeCorrectType)
	})
}
