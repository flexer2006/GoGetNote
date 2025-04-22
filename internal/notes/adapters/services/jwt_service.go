// Package services provides implementations of service interfaces.
package services

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/golang-jwt/jwt/v5"
	"go.uber.org/zap"

	"gogetnote/internal/notes/ports/services"
	"gogetnote/pkg/logger"
)

// Константы для работы с JWT.
const (
	methodValidateToken = "ValidateAccessToken"
	msgValidatingToken  = "validating token"
	msgTokenValidated   = "token validated successfully"
	msgInvalidToken     = "invalid token format"
	msgTokenExpired     = "token has expired"
	msgErrParsingToken  = "error parsing token" //nolint:gosec
	errCtxValidating    = "validating token"
)

// ErrInvalidAlgorithm представляет статическую ошибку неверного алгоритма подписи.
var ErrInvalidAlgorithm = errors.New("invalid signing algorithm")

// Claims используется для адаптации между доменной моделью и библиотекой JWT.
type Claims struct {
	UserID   string `json:"user_id"`
	Username string `json:"username"`
	jwt.RegisteredClaims
}

// ServiceJWT реализует интерфейс TokenService.
type ServiceJWT struct {
	secretKey []byte
}

// NewJWT создает новый экземпляр сервиса JWT.
func NewJWT(secretKey string) services.TokenService {
	return &ServiceJWT{
		secretKey: []byte(secretKey),
	}
}

// ValidateAccessToken проверяет JWT токен и возвращает ID пользователя.
func (s *ServiceJWT) ValidateAccessToken(ctx context.Context, tokenString string) (string, error) {
	log := logger.Log(ctx).With(zap.String("method", methodValidateToken))
	log.Debug(ctx, msgValidatingToken)

	token, err := jwt.ParseWithClaims(tokenString, &Claims{}, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("%w: %v", ErrInvalidAlgorithm, token.Header["alg"])
		}
		return s.secretKey, nil
	})

	if err != nil {
		if strings.Contains(err.Error(), "token is expired") {
			log.Debug(ctx, msgTokenExpired)
			return "", fmt.Errorf("%s: %w", errCtxValidating, services.ErrExpiredJWTToken)
		}
		log.Error(ctx, msgErrParsingToken, zap.Error(err))
		return "", fmt.Errorf("%s: %w", errCtxValidating, services.ErrInvalidJWTToken)
	}

	claims, ok := token.Claims.(*Claims)
	if !ok || !token.Valid {
		log.Debug(ctx, msgInvalidToken)
		return "", fmt.Errorf("%s: %w", errCtxValidating, services.ErrInvalidJWTToken)
	}

	if claims.UserID == "" {
		log.Debug(ctx, "user_id claim is empty")
		return "", fmt.Errorf("%s: %w", errCtxValidating, services.ErrInvalidJWTToken)
	}

	log.Debug(ctx, msgTokenValidated, zap.String("userID", claims.UserID))
	return claims.UserID, nil
}
