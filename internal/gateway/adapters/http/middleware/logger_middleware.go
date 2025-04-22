// Package middleware содержит промежуточное ПО для HTTP обработчиков.
package middleware

import (
	"fmt"
	"time"

	"github.com/gofiber/fiber/v3"
	"go.uber.org/zap"

	"gogetnote/pkg/logger"
)

// NewLoggerMiddleware создает новое промежуточное ПО для логирования HTTP запросов.
func NewLoggerMiddleware() fiber.Handler {
	return func(ctx fiber.Ctx) error {
		requestCtx := ctx.Context()
		start := time.Now()
		path := ctx.Path()
		method := ctx.Method()

		log := logger.Log(requestCtx).With(
			zap.String("path", path),
			zap.String("method", method),
			zap.String("ip", ctx.IP()),
		)

		log.Info(requestCtx, "Request started")

		err := ctx.Next()

		latency := time.Since(start)
		status := ctx.Response().StatusCode()

		logFields := []zap.Field{
			zap.Int("status", status),
			zap.Duration("latency", latency),
		}

		if err != nil {
			log.Error(requestCtx, "Request failed", append(logFields, zap.Error(err))...)
			return fmt.Errorf("request processing error: %w", err)
		}

		log.Info(requestCtx, "Request completed", logFields...)
		return nil
	}
}
