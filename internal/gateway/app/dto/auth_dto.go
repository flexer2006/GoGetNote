// Package dto содержит объекты передачи данных для Gateway.
package dto

import (
	"time"
)

// RegisterRequest содержит данные для регистрации пользователя.
type RegisterRequest struct {
	Email    string `json:"email" validate:"required,email"`
	Username string `json:"username" validate:"required,min=3,max=50"`
	Password string `json:"password" validate:"required,min=8"`
}

// LoginRequest содержит данные для входа пользователя.
type LoginRequest struct {
	Email    string `json:"email" validate:"required,email"`
	Password string `json:"password" validate:"required"`
}

// TokenResponse содержит данные о токенах.
type TokenResponse struct {
	UserID       string    `json:"user_id"`
	Username     string    `json:"username,omitempty"`
	AccessToken  string    `json:"access_token"`
	RefreshToken string    `json:"refresh_token"`
	ExpiresAt    time.Time `json:"expires_at"`
}

// RefreshRequest содержит данные для обновления токенов.
type RefreshRequest struct {
	RefreshToken string `json:"refresh_token" validate:"required"`
}

// LogoutRequest содержит данные для выхода пользователя.
type LogoutRequest struct {
	RefreshToken string `json:"refresh_token" validate:"required"`
}

// UserProfileResponse содержит данные профиля пользователя.
type UserProfileResponse struct {
	UserID    string    `json:"user_id"`
	Email     string    `json:"email"`
	Username  string    `json:"username"`
	CreatedAt time.Time `json:"created_at"`
}
