// Package services предоставляет фабрику для создания и доступа к различным сервисам аутентификации,
// таким как сервисы работы с паролями и JWT токенами.
package services

import (
	"time"

	"gogetnote/internal/auth/ports/services"
)

// ServiceFactory создает все необходимые сервисы для аутентификации.
type ServiceFactory struct {
	passwordService services.PasswordService
	tokenService    services.TokenService
}

// NewServiceFactory создает новую фабрику сервисов с настройками по умолчанию.
func NewServiceFactory(
	jwtSecretKey string,
	accessTokenTTL, refreshTokenTTL time.Duration,
	bcryptCost int,
) *ServiceFactory {
	return &ServiceFactory{
		passwordService: NewBcrypt(bcryptCost),
		tokenService:    NewJWT(jwtSecretKey, accessTokenTTL, refreshTokenTTL),
	}
}

// PasswordService возвращает сервис для работы с паролями.
func (f *ServiceFactory) PasswordService() services.PasswordService {
	return f.passwordService
}

// TokenService возвращает сервис для работы с токенами.
func (f *ServiceFactory) TokenService() services.TokenService {
	return f.tokenService
}
