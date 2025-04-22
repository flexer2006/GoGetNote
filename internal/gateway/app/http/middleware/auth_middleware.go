// Package middleware содержит промежуточное ПО для HTTP обработчиков
package middleware

import (
	"fmt"
	"strings"

	"github.com/gofiber/fiber/v3"
	"go.uber.org/zap"
	"google.golang.org/grpc/metadata"

	"gogetnote/pkg/logger"
)

// Константы для логирования.
const (
	LogAuthMiddleware = "auth middleware"

	ErrorNoAuthHeader       = "no authorization header provided"
	ErrorInvalidTokenFormat = "invalid token format"
)

// NewAuthMiddleware создает новое промежуточное ПО для проверки аутентификации.
func NewAuthMiddleware() fiber.Handler {
	return func(ctx fiber.Ctx) error {
		requestCtx := ctx.Context()
		log := logger.Log(requestCtx).With(zap.String("middleware", "auth"))
		log.Debug(requestCtx, LogAuthMiddleware)

		authHeader := ctx.Get("Authorization")
		if authHeader == "" {
			log.Debug(requestCtx, ErrorNoAuthHeader)
			return fmt.Errorf("%s: %w", ErrorNoAuthHeader,
				ctx.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
					"error": ErrorNoAuthHeader,
				}))
		}

		if !strings.HasPrefix(authHeader, "Bearer ") {
			log.Debug(requestCtx, ErrorInvalidTokenFormat)
			return fmt.Errorf("%s: %w", ErrorInvalidTokenFormat,
				ctx.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
					"error": ErrorInvalidTokenFormat,
				}))
		}

		md := metadata.New(map[string]string{
			"authorization": authHeader,
		})
		newCtx := metadata.NewIncomingContext(requestCtx, md)

		ctx.Locals("userContext", newCtx)

		return ctx.Next()
	}
}
