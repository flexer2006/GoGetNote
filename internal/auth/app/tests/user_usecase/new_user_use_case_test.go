package userusecase_test

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"gogetnote/internal/auth/app"
	"gogetnote/internal/auth/ports/api"
)

func TestNewUserUseCase(t *testing.T) {
	mockRepo := new(mockUserRepository)

	useCase := app.NewUserUseCase(mockRepo)

	assert.NotNil(t, useCase, "NewUserUseCase должен возвращать не-nil объект")

	_, ok := useCase.(api.UserUseCase)
	assert.True(t, ok, "Возвращаемый объект должен реализовывать интерфейс api.UserUseCase")

	_, ok = useCase.(*app.UserUseCaseImpl)
	assert.True(t, ok, "Возвращаемый объект должен быть типа *app.UserUseCaseImpl")
}
