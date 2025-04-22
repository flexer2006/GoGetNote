// Package auth содержит HTTP обработчики для работы с сервисом авторизации.
package auth

import (
	"context"
	"fmt"
	"net/http"

	"github.com/gofiber/fiber/v3"
	"go.uber.org/zap"

	"gogetnote/internal/gateway/app/dto"
	"gogetnote/internal/gateway/ports/services"
	"gogetnote/pkg/logger"
)

// Константы для логирования.
const (
	LogHandlerRegister      = "auth handler: register"
	LogHandlerLogin         = "auth handler: login"
	LogHandlerRefreshTokens = "auth handler: refresh tokens" // #nosec G101 - not a credential
	LogHandlerLogout        = "auth handler: logout"
	LogHandlerGetProfile    = "auth handler: get profile"

	ErrorInvalidRequest       = "invalid request"
	ErrorFailedToServeRequest = "failed to serve request"
)

// Handler содержит HTTP обработчики для авторизации.
type Handler struct {
	authService services.AuthService
}

// NewHandler создает новый экземпляр обработчика авторизации.
func NewHandler(authService services.AuthService) *Handler {
	return &Handler{
		authService: authService,
	}
}

// Register обрабатывает запрос на регистрацию нового пользователя.
func (h *Handler) Register(ctx fiber.Ctx) error {
	requestCtx := ctx.Context()
	log := logger.Log(requestCtx)
	log.Info(requestCtx, LogHandlerRegister)

	var req dto.RegisterRequest
	if err := ctx.Bind().JSON(&req); err != nil {
		log.Error(requestCtx, ErrorInvalidRequest, zap.Error(err))
		return fmt.Errorf("binding JSON: %w", ctx.Status(http.StatusBadRequest).JSON(fiber.Map{
			"error": ErrorInvalidRequest,
		}))
	}

	if req.Email == "" || req.Username == "" || req.Password == "" {
		return fmt.Errorf("validating request: %w", ctx.Status(http.StatusBadRequest).JSON(fiber.Map{
			"error": "email, username and password are required",
		}))
	}

	response, err := h.authService.Register(requestCtx, &req)
	if err != nil {
		log.Error(requestCtx, ErrorFailedToServeRequest, zap.Error(err))
		return fmt.Errorf("registering user: %w", ctx.Status(http.StatusInternalServerError).JSON(fiber.Map{
			"error": err.Error(),
		}))
	}

	if err := ctx.Status(http.StatusCreated).JSON(response); err != nil {
		return fmt.Errorf("sending response: %w", err)
	}
	return nil
}

// Login обрабатывает запрос на вход пользователя.
func (h *Handler) Login(ctx fiber.Ctx) error {
	requestCtx := ctx.Context()
	log := logger.Log(requestCtx)
	log.Info(requestCtx, LogHandlerLogin)

	var req dto.LoginRequest
	if err := ctx.Bind().JSON(&req); err != nil {
		log.Error(requestCtx, ErrorInvalidRequest, zap.Error(err))
		return fmt.Errorf("binding JSON: %w", ctx.Status(http.StatusBadRequest).JSON(fiber.Map{
			"error": ErrorInvalidRequest,
		}))
	}

	if req.Email == "" || req.Password == "" {
		return fmt.Errorf("validating request: %w", ctx.Status(http.StatusBadRequest).JSON(fiber.Map{
			"error": "email and password are required",
		}))
	}

	response, err := h.authService.Login(requestCtx, &req)
	if err != nil {
		log.Error(requestCtx, ErrorFailedToServeRequest, zap.Error(err))
		return fmt.Errorf("logging in: %w", ctx.Status(http.StatusUnauthorized).JSON(fiber.Map{
			"error": err.Error(),
		}))
	}

	if err := ctx.Status(http.StatusOK).JSON(response); err != nil {
		return fmt.Errorf("sending response: %w", err)
	}
	return nil
}

// RefreshTokens обрабатывает запрос на обновление токенов.
func (h *Handler) RefreshTokens(ctx fiber.Ctx) error {
	requestCtx := ctx.Context()
	log := logger.Log(requestCtx)
	log.Info(requestCtx, LogHandlerRefreshTokens)

	var req dto.RefreshRequest
	if err := ctx.Bind().JSON(&req); err != nil {
		log.Error(requestCtx, ErrorInvalidRequest, zap.Error(err))
		return fmt.Errorf("binding JSON: %w", ctx.Status(http.StatusBadRequest).JSON(fiber.Map{
			"error": ErrorInvalidRequest,
		}))
	}

	if req.RefreshToken == "" {
		return fmt.Errorf("validating request: %w", ctx.Status(http.StatusBadRequest).JSON(fiber.Map{
			"error": "refresh token is required",
		}))
	}

	response, err := h.authService.RefreshTokens(requestCtx, &req)
	if err != nil {
		log.Error(requestCtx, ErrorFailedToServeRequest, zap.Error(err))
		return fmt.Errorf("refreshing tokens: %w", ctx.Status(http.StatusUnauthorized).JSON(fiber.Map{
			"error": err.Error(),
		}))
	}

	if err := ctx.Status(http.StatusOK).JSON(response); err != nil {
		return fmt.Errorf("sending response: %w", err)
	}
	return nil
}

// Logout обрабатывает запрос на выход пользователя.
func (h *Handler) Logout(ctx fiber.Ctx) error {
	requestCtx := ctx.Context()
	log := logger.Log(requestCtx)
	log.Info(requestCtx, LogHandlerLogout)

	var req dto.LogoutRequest
	if err := ctx.Bind().JSON(&req); err != nil {
		log.Error(requestCtx, ErrorInvalidRequest, zap.Error(err))
		return fmt.Errorf("binding JSON: %w", ctx.Status(http.StatusBadRequest).JSON(fiber.Map{
			"error": ErrorInvalidRequest,
		}))
	}

	if req.RefreshToken == "" {
		return fmt.Errorf("validating request: %w", ctx.Status(http.StatusBadRequest).JSON(fiber.Map{
			"error": "refresh token is required",
		}))
	}

	err := h.authService.Logout(requestCtx, &req)
	if err != nil {
		log.Error(requestCtx, ErrorFailedToServeRequest, zap.Error(err))
		return fmt.Errorf("logging out: %w", ctx.Status(http.StatusInternalServerError).JSON(fiber.Map{
			"error": err.Error(),
		}))
	}

	if err := ctx.Status(http.StatusOK).JSON(fiber.Map{
		"message": "logged out successfully",
	}); err != nil {
		return fmt.Errorf("sending response: %w", err)
	}
	return nil
}

// GetProfile обрабатывает запрос на получение профиля пользователя.
func (h *Handler) GetProfile(ctx fiber.Ctx) error {
	requestCtx := ctx.Context()
	log := logger.Log(requestCtx)
	log.Info(requestCtx, LogHandlerGetProfile)

	userCtx, ok := ctx.Locals("userContext").(context.Context)
	if !ok {
		return fmt.Errorf("getting user context: %w", ctx.Status(http.StatusUnauthorized).JSON(fiber.Map{
			"error": "unauthorized",
		}))
	}

	profile, err := h.authService.GetUserProfile(userCtx)
	if err != nil {
		log.Error(requestCtx, ErrorFailedToServeRequest, zap.Error(err))
		return fmt.Errorf("getting user profile: %w", ctx.Status(http.StatusUnauthorized).JSON(fiber.Map{
			"error": err.Error(),
		}))
	}

	if err := ctx.Status(http.StatusOK).JSON(profile); err != nil {
		return fmt.Errorf("sending response: %w", err)
	}
	return nil
}
