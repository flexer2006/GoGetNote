// Package http содержит компоненты для HTTP сервера.
package http

import (
	"github.com/gofiber/fiber/v3"

	"gogetnote/internal/gateway/app/http/auth"
	"gogetnote/internal/gateway/app/http/middleware"
	"gogetnote/internal/gateway/ports/services"
)

// SetupRouter настраивает маршрутизацию для HTTP сервера.
func SetupRouter(app *fiber.App, authService services.AuthService) {
	authHandler := auth.NewHandler(authService)

	// Middleware для всех запросов.
	app.Use(middleware.NewLoggerMiddleware())
	app.Use(middleware.NewRecoveryMiddleware())

	// API версии 1.
	apiV1 := app.Group("/api/v1")

	// Auth routes (публичные).
	authRoutes := apiV1.Group("/auth")
	authRoutes.Post("/register", authHandler.Register)
	authRoutes.Post("/login", authHandler.Login)
	authRoutes.Post("/refresh", authHandler.RefreshTokens)
	authRoutes.Post("/logout", authHandler.Logout)

	// Защищенные маршруты.
	userRoutes := apiV1.Group("/user")
	userRoutes.Use(middleware.NewAuthMiddleware())
	userRoutes.Get("/profile", authHandler.GetProfile)

	// Обработчик для несуществующих маршрутов.
	app.Use(func(c fiber.Ctx) error {
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{
			"error": "Route not found",
		})
	})
}
