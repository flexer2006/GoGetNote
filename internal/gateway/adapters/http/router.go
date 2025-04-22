// Package http содержит компоненты для HTTP сервера.
package http

import (
	"github.com/gofiber/fiber/v3"

	"gogetnote/internal/gateway/adapters/http/auth"
	"gogetnote/internal/gateway/adapters/http/middleware"
	"gogetnote/internal/gateway/adapters/http/notes"
	"gogetnote/internal/gateway/ports/services"
)

// SetupRouter настраивает маршрутизацию для HTTP сервера.
func SetupRouter(app *fiber.App, authService services.AuthService, notesService services.NotesService) {
	authHandler := auth.NewHandler(authService)
	notesHandler := notes.NewHandler(notesService)

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

	// Маршруты заметок (требуют авторизации).
	notesRoutes := apiV1.Group("/notes")
	notesRoutes.Use(middleware.NewAuthMiddleware())
	notesRoutes.Post("/", notesHandler.CreateNote)
	notesRoutes.Get("/:note_id", notesHandler.GetNote)
	notesRoutes.Get("/", notesHandler.ListNotes)
	notesRoutes.Patch("/:note_id", notesHandler.UpdateNote)
	notesRoutes.Put("/:note_id", notesHandler.UpdateNote)
	notesRoutes.Delete("/:note_id", notesHandler.DeleteNote)

	// Обработчик для несуществующих маршрутов.
	app.Use(func(c fiber.Ctx) error {
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{
			"error": "Route not found",
		})
	})
}
