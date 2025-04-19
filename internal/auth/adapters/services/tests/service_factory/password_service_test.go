package service_factory_test

import (
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/bcrypt"
	"testing"

	"gogetnote/internal/auth/adapters/services"
)

const (
	errMsgSvcShouldNotNil = "password service should not be nil"
	errMsgShouldBeService = "returned service should be of correct type"
	errMsgShouldBeTheSame = "should return the same service instance on multiple calls"
)

func TestServiceFactory_PasswordService(t *testing.T) {
	t.Run("returns non-nil password service", func(t *testing.T) {
		factory := services.NewServiceFactory(
			defaultJWTSecretKey,
			defaultAccessTokenTTL,
			defaultRefreshTokenTTL,
			defaultBcryptCost,
		)

		passwordService := factory.PasswordService()

		require.NotNil(t, passwordService, errMsgSvcShouldNotNil)
		assert.IsType(t, &services.ServiceJWT{}, passwordService, errMsgShouldBeService)
	})

	t.Run("returns same instance on multiple calls", func(t *testing.T) {
		factory := services.NewServiceFactory(
			defaultJWTSecretKey,
			defaultAccessTokenTTL,
			defaultRefreshTokenTTL,
			defaultBcryptCost,
		)

		service1 := factory.PasswordService()
		service2 := factory.PasswordService()

		assert.Same(t, service1, service2, errMsgShouldBeTheSame)
	})

	t.Run("with minimal bcrypt cost", func(t *testing.T) {
		factory := services.NewServiceFactory(
			defaultJWTSecretKey,
			defaultAccessTokenTTL,
			defaultRefreshTokenTTL,
			bcrypt.MinCost-1,
		)

		passwordService := factory.PasswordService()

		require.NotNil(t, passwordService, errMsgSvcShouldNotNil)
		assert.IsType(t, &services.ServiceJWT{}, passwordService, errMsgShouldBeService)
	})
}
