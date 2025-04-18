package entities

import (
	"errors"
	"time"
)

// Определяем ошибки домена пользователя как константы.
var (
	ErrEmptyUserID      = errors.New("user ID cannot be empty")
	ErrInvalidEmail     = errors.New("invalid email format")
	ErrEmptyUsername    = errors.New("username cannot be empty")
	ErrPasswordTooShort = errors.New("password must contain at least 8 characters")
	ErrPasswordTooWeak  = errors.New("password must contain at least one letter and one digit")
	ErrUserNotFound     = errors.New("user not found")
)

// User представляет основную сущность домена пользователя.
type User struct {
	ID           string
	Email        string
	Username     string
	PasswordHash string
	CreatedAt    time.Time
	UpdatedAt    time.Time
}
