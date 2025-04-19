package service_factory_test

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"golang.org/x/crypto/bcrypt"

	"gogetnote/internal/auth/adapters/services"
)

const (
	defaultJWTSecretKey     = "test-secret-key"
	defaultAccessTokenTTL   = 15 * time.Minute
	defaultRefreshTokenTTL  = 24 * time.Hour
	defaultBcryptCost       = 10
	errMsgServiceInitFailed = "service factory should properly initialize services"
	errMsgFactoryNotNil     = "service factory should not be nil"
	errMsgPasswordSvcNotNil = "password service should not be nil"
	errMsgTokenSvcNotNil    = "token service should not be nil"
)

func Test_NewServiceFactory(t *testing.T) {
	factory := services.NewServiceFactory(
		defaultJWTSecretKey,
		defaultAccessTokenTTL,
		defaultRefreshTokenTTL,
		defaultBcryptCost,
	)

	assert.NotNil(t, factory, errMsgFactoryNotNil)
	assert.NotNil(t, factory.PasswordService(), errMsgPasswordSvcNotNil)
	assert.NotNil(t, factory.TokenService(), errMsgTokenSvcNotNil)

	passwordService := factory.PasswordService()
	tokenService := factory.TokenService()

	assert.IsType(t, &services.ServiceJWT{}, passwordService, errMsgServiceInitFailed)
	assert.IsType(t, &services.ServiceJWT{}, tokenService, errMsgServiceInitFailed)
}

func Test_NewServiceFactory_WithMinimalBcryptCost(t *testing.T) {
	factory := services.NewServiceFactory(
		defaultJWTSecretKey,
		defaultAccessTokenTTL,
		defaultRefreshTokenTTL,
		bcrypt.MinCost-1,
	)

	assert.NotNil(t, factory, errMsgFactoryNotNil)
	assert.NotNil(t, factory.PasswordService(), errMsgPasswordSvcNotNil)
}

func Test_NewServiceFactory_WithEmptyJWTKey(t *testing.T) {
	factory := services.NewServiceFactory(
		"",
		defaultAccessTokenTTL,
		defaultRefreshTokenTTL,
		defaultBcryptCost,
	)

	assert.NotNil(t, factory, errMsgFactoryNotNil)
	assert.NotNil(t, factory.TokenService(), errMsgTokenSvcNotNil)
}

func Test_NewServiceFactory_WithZeroDurations(t *testing.T) {
	factory := services.NewServiceFactory(
		defaultJWTSecretKey,
		0,
		0,
		defaultBcryptCost,
	)

	assert.NotNil(t, factory, errMsgFactoryNotNil)
	assert.NotNil(t, factory.TokenService(), errMsgTokenSvcNotNil)
}
