package authusecase_test

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"gogetnote/internal/auth/app"
	"gogetnote/internal/auth/ports/api"
)

func TestNewAuthUseCase(t *testing.T) {
	mockUserRepo := new(mockUserRepository)
	mockTokenRepo := new(mockTokenRepository)
	mockPasswordSvc := new(mockPasswordService)
	mockTokenSvc := new(mockTokenService)

	useCase := app.NewAuthUseCase(mockUserRepo, mockTokenRepo, mockPasswordSvc, mockTokenSvc)

	assert.NotNil(t, useCase)

	_, ok := useCase.(api.AuthUseCase)
	assert.True(t, ok)
}
