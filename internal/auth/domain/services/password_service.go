package services

import (
	"errors"
)

// PasswordErrors содержит ошибки, связанные с паролями.
var (
	ErrHashingFailed   = errors.New("failed to hash password")
	ErrInvalidPassword = errors.New("invalid password")
)

// MinPasswordLength - минимальная длина пароля.
const MinPasswordLength = 8
