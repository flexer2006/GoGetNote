package services

import (
	"context"
	"errors"
	"fmt"

	"golang.org/x/crypto/bcrypt"

	"gogetnote/internal/auth/domain/services"
	svc "gogetnote/internal/auth/ports/services"
)

const (
	errMsgFailedToGenerateHash = "failed to generate password hash"
	errMsgErrorComparingHash   = "error comparing password with hash"
	errMsgPasswordTooShort     = "password is too short"
)

// ServiceBcrypt реализует интерфейс PasswordService.
type ServiceBcrypt struct {
	cost int
}

// NewBcrypt создает новый экземпляр сервиса bcrypt.
func NewBcrypt(cost int) svc.PasswordService {
	if cost < bcrypt.MinCost {
		cost = bcrypt.DefaultCost
	}
	return &ServiceBcrypt{cost: cost}
}

// Hash хэширует пароль с помощью bcrypt.
func (s *ServiceBcrypt) Hash(_ context.Context, password string) (string, error) {
	if password == "" {
		return "", services.ErrInvalidPassword
	}

	if len(password) < services.MinPasswordLength {
		return "", fmt.Errorf("%s: %w", errMsgPasswordTooShort, services.ErrInvalidPassword)
	}

	hashedBytes, err := bcrypt.GenerateFromPassword([]byte(password), s.cost)
	if err != nil {
		return "", fmt.Errorf("%s: %w", errMsgFailedToGenerateHash, services.ErrHashingFailed)
	}

	return string(hashedBytes), nil
}

// Verify проверяет соответствие пароля хэшу.
func (s *ServiceBcrypt) Verify(_ context.Context, password, hash string) (bool, error) {
	if password == "" || hash == "" {
		return false, services.ErrInvalidPassword
	}

	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	if err != nil {
		if errors.Is(err, bcrypt.ErrMismatchedHashAndPassword) {
			return false, nil
		}
		return false, fmt.Errorf("%s: %w", errMsgErrorComparingHash, err)
	}

	return true, nil
}
