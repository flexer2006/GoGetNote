package userusecase_test

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"gogetnote/internal/auth/app"
)

const msgReturnNonNilObject = "NewUserUseCase should return a non-nil object"

func TestNewUserUseCase(t *testing.T) {
	mockRepo := new(mockUserRepository)

	useCase := app.NewUserUseCase(mockRepo)

	assert.NotNil(t, useCase, msgReturnNonNilObject)
}
