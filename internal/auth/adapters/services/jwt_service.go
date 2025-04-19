package services

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"go.uber.org/zap"

	"gogetnote/internal/auth/domain/services"
	svc "gogetnote/internal/auth/ports/services"
	"gogetnote/pkg/logger"
)

// Константы для работы с JWT.
const (
	methodGenerateAccessToken  = "GenerateAccessToken"
	methodGenerateRefreshToken = "GenerateRefreshToken"
	methodValidateAccessToken  = "ValidateAccessToken"
	msgGeneratingAccessToken   = "generating access token"
	msgGeneratingRefreshToken  = "generating refresh token"
	msgValidatingToken         = "validating token"
	msgTokenGenerated          = "token generated successfully"
	msgTokenValidated          = "token validated successfully"
	msgInvalidToken            = "invalid token format"
	msgTokenExpired            = "token has expired"
	//nolint:gosec
	errSigningToken = "error signing token"
	//nolint:gosec
	errParsingToken       = "error parsing token"
	errCtxGeneratingToken = "generating token"
	errCtxParsingToken    = "parsing token"
	errCtxValidatingToken = "validating token"
)

// ErrInvalidAlgorithm представляет статическую ошибку неверного алгоритма подписи.
var ErrInvalidAlgorithm = errors.New("invalid signing algorithm")

// Claims используется для адаптации между доменной моделью и библиотекой JWT.
type Claims struct {
	UserID   string `json:"user_id"`
	Username string `json:"username"`
	jwt.RegisteredClaims
}

// ClaimsJwt определен для обратной совместимости с тестами.
type ClaimsJwt = Claims

// ServiceJWT  реализует интерфейс.
type ServiceJWT struct {
	config services.JWTConfig
}

// NewJWT создает новый экземпляр сервиса JWT.
func NewJWT(secretKey string, accessTokenTTL, refreshTokenTTL time.Duration) svc.TokenService {
	return &ServiceJWT{
		config: services.JWTConfig{
			SecretKey:       []byte(secretKey),
			AccessTokenTTL:  accessTokenTTL,
			RefreshTokenTTL: refreshTokenTTL,
		},
	}
}

// domainToJWTClaims преобразует доменные claims в формат библиотеки JWT.
func domainToJWTClaims(claims services.JWTClaims) Claims {
	return Claims{
		UserID:   claims.UserID,
		Username: claims.Username,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(claims.ExpiresAt),
			IssuedAt:  jwt.NewNumericDate(claims.IssuedAt),
			Subject:   claims.UserID,
		},
	}
}

// GetDomainToJWTClaimsForTest возвращает Claims для тестирования, трансформируя из доменной модели.
func GetDomainToJWTClaimsForTest(claims services.JWTClaims) Claims {
	return domainToJWTClaims(claims)
}

// jwtToDomainClaims преобразует claims формата библиотеки JWT в доменные claims.
func jwtToDomainClaims(claims Claims) services.JWTClaims {
	var expiresAt, issuedAt time.Time
	if claims.ExpiresAt != nil {
		expiresAt = claims.ExpiresAt.Time
	}
	if claims.IssuedAt != nil {
		issuedAt = claims.IssuedAt.Time
	}

	return services.JWTClaims{
		UserID:    claims.UserID,
		Username:  claims.Username,
		ExpiresAt: expiresAt,
		IssuedAt:  issuedAt,
	}
}

// GetJWTToDomainClaimsForTest экспортирует функцию jwtToDomainClaims для тестирования.
func GetJWTToDomainClaimsForTest(claims Claims) services.JWTClaims {
	return jwtToDomainClaims(claims)
}

// GenerateAccessToken генерирует JWT токен доступа.
func (s *ServiceJWT) GenerateAccessToken(ctx context.Context, userID, username string) (string, time.Time, error) {
	log := logger.Log(ctx).With(
		zap.String("method", methodGenerateAccessToken),
		zap.String("userID", userID),
	)
	log.Debug(ctx, msgGeneratingAccessToken)

	// Проверка на пустой секретный ключ
	if len(s.config.SecretKey) == 0 {
		log.Error(ctx, "empty secret key provided")
		return "", time.Time{}, fmt.Errorf("%s: %w: empty secret key", errCtxGeneratingToken, services.ErrGeneratingJWTToken)
	}

	now := time.Now()
	expiresAt := now.Add(s.config.AccessTokenTTL)

	domainClaims := services.JWTClaims{
		UserID:    userID,
		Username:  username, // Обратите внимание, что пустая строка это валидное значение
		IssuedAt:  now,
		ExpiresAt: expiresAt,
	}

	jwtClaims := domainToJWTClaims(domainClaims)

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwtClaims)

	tokenString, err := token.SignedString(s.config.SecretKey)
	if err != nil {
		log.Error(ctx, errSigningToken, zap.Error(err))
		return "", time.Time{}, fmt.Errorf("%s: %w: %w", errCtxGeneratingToken, services.ErrGeneratingJWTToken, err)
	}

	log.Debug(ctx, msgTokenGenerated, zap.Time("expiresAt", expiresAt))
	return tokenString, expiresAt, nil
}

// GenerateRefreshToken генерирует refresh токен.
func (s *ServiceJWT) GenerateRefreshToken(ctx context.Context, userID string) (string, time.Time, error) {
	log := logger.Log(ctx).With(
		zap.String("method", methodGenerateRefreshToken),
		zap.String("userID", userID),
	)
	log.Debug(ctx, msgGeneratingRefreshToken)

	// Проверка на пустой секретный ключ
	if len(s.config.SecretKey) == 0 {
		log.Error(ctx, "empty secret key provided")
		return "", time.Time{}, fmt.Errorf("%s: %w: empty secret key", errCtxGeneratingToken, services.ErrGeneratingJWTToken)
	}

	now := time.Now()
	expiresAt := now.Add(s.config.RefreshTokenTTL)

	domainClaims := services.JWTClaims{
		UserID:    userID,
		IssuedAt:  now,
		ExpiresAt: expiresAt,
	}

	jwtClaims := domainToJWTClaims(domainClaims)

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwtClaims)

	tokenString, err := token.SignedString(s.config.SecretKey)
	if err != nil {
		log.Error(ctx, errSigningToken, zap.Error(err))
		return "", time.Time{}, fmt.Errorf("%s: %w: %w", errCtxGeneratingToken, services.ErrGeneratingJWTToken, err)
	}

	log.Debug(ctx, msgTokenGenerated, zap.Time("expiresAt", expiresAt))
	return tokenString, expiresAt, nil
}

// ValidateAccessToken проверяет JWT токен и возвращает ID пользователя.
func (s *ServiceJWT) ValidateAccessToken(ctx context.Context, tokenString string) (string, error) {
	log := logger.Log(ctx).With(zap.String("method", methodValidateAccessToken))
	log.Debug(ctx, msgValidatingToken)

	token, err := jwt.ParseWithClaims(tokenString, &Claims{}, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("%w: %v", ErrInvalidAlgorithm, token.Header["alg"])
		}
		return s.config.SecretKey, nil
	})

	if err != nil {
		if strings.Contains(err.Error(), "token is expired") {
			log.Debug(ctx, msgTokenExpired)
			return "", fmt.Errorf("%s: %w", errCtxValidatingToken, services.ErrExpiredJWTToken)
		}
		log.Error(ctx, errParsingToken, zap.Error(err))
		return "", fmt.Errorf("%s: %w: %w", errCtxParsingToken, services.ErrInvalidJWTToken, err)
	}

	claims, ok := token.Claims.(*Claims)
	if !ok || !token.Valid {
		log.Debug(ctx, msgInvalidToken)
		return "", fmt.Errorf("%s: %w", errCtxValidatingToken, services.ErrInvalidJWTToken)
	}

	if claims.UserID == "" {
		log.Debug(ctx, "user_id claim is empty")
		return "", fmt.Errorf("%s: %w: empty user_id", errCtxValidatingToken, services.ErrInvalidJWTToken)
	}

	log.Debug(ctx, msgTokenValidated, zap.String("userID", claims.UserID))
	return claims.UserID, nil
}
