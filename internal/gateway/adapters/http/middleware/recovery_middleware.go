// Package middleware содержит промежуточное ПО для HTTP обработчиков.
package middleware

import (
	"fmt"
	"runtime/debug"

	"github.com/gofiber/fiber/v3"
	"go.uber.org/zap"

	"gogetnote/pkg/logger"
)

// NewRecoveryMiddleware создает новое промежуточное ПО для восстановления после паники.
func NewRecoveryMiddleware() fiber.Handler {
	return func(ctx fiber.Ctx) error {
		requestCtx := ctx.Context()
		log := logger.Log(requestCtx)

		defer func() {
			if r := recover(); r != nil {
				stack := debug.Stack()

				log.Error(requestCtx, "Server panic",
					zap.String("error", fmt.Sprintf("%v", r)),
					zap.String("stack", string(stack)),
				)

				if err := ctx.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
					"error": "Internal Server Error",
				}); err != nil {
					log.Error(requestCtx, "Failed to send error response after panic", zap.Error(err))
				}
			}
		}()

		return ctx.Next()
	}
}
