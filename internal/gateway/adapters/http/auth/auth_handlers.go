// Package auth содержит HTTP обработчики для работы с сервисом авторизации.
package auth

import (
	"context"
	"fmt"
	"net/http"
	"strings"

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

// Вспомогательная функция для обработки ошибок HTTP.
func sendErrorResponse(ctx fiber.Ctx, statusCode int, message string) error {
	if err := ctx.Status(statusCode).JSON(fiber.Map{
		"error": message,
	}); err != nil {
		return fmt.Errorf("error sending response: %w", err)
	}
	return nil
}

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
		if err := ctx.Status(http.StatusBadRequest).JSON(fiber.Map{
			"error": ErrorInvalidRequest,
		}); err != nil {
			return fmt.Errorf("error sending bad request response: %w", err)
		}
		return nil
	}

	if req.Email == "" || req.Username == "" || req.Password == "" {
		if err := ctx.Status(http.StatusBadRequest).JSON(fiber.Map{
			"error": "email, username and password are required",
		}); err != nil {
			return fmt.Errorf("error sending validation error response: %w", err)
		}
		return nil
	}

	response, err := h.authService.Register(requestCtx, &req)
	if err != nil {
		log.Error(requestCtx, ErrorFailedToServeRequest, zap.Error(err))
		statusCode := http.StatusInternalServerError
		if strings.Contains(err.Error(), "user already exists") {
			statusCode = http.StatusConflict
		}
		return sendErrorResponse(ctx, statusCode, err.Error())
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
		return sendErrorResponse(ctx, http.StatusBadRequest, ErrorInvalidRequest)
	}

	if req.Email == "" || req.Password == "" {
		return sendErrorResponse(ctx, http.StatusBadRequest, "email and password are required")
	}

	response, err := h.authService.Login(requestCtx, &req)
	if err != nil {
		log.Error(requestCtx, ErrorFailedToServeRequest, zap.Error(err))
		return sendErrorResponse(ctx, http.StatusUnauthorized, err.Error())
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
		return sendErrorResponse(ctx, http.StatusBadRequest, ErrorInvalidRequest)
	}

	if req.RefreshToken == "" {
		return sendErrorResponse(ctx, http.StatusBadRequest, "refresh token is required")
	}

	response, err := h.authService.RefreshTokens(requestCtx, &req)
	if err != nil {
		log.Error(requestCtx, ErrorFailedToServeRequest, zap.Error(err))
		return sendErrorResponse(ctx, http.StatusUnauthorized, err.Error())
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
		return sendErrorResponse(ctx, http.StatusBadRequest, ErrorInvalidRequest)
	}

	if req.RefreshToken == "" {
		return sendErrorResponse(ctx, http.StatusBadRequest, "refresh token is required")
	}

	err := h.authService.Logout(requestCtx, &req)
	if err != nil {
		log.Error(requestCtx, ErrorFailedToServeRequest, zap.Error(err))
		return sendErrorResponse(ctx, http.StatusInternalServerError, err.Error())
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
		return sendErrorResponse(ctx, http.StatusUnauthorized, "unauthorized")
	}

	profile, err := h.authService.GetUserProfile(userCtx)
	if err != nil {
		log.Error(requestCtx, ErrorFailedToServeRequest, zap.Error(err))
		return sendErrorResponse(ctx, http.StatusUnauthorized, err.Error())
	}

	if err := ctx.Status(http.StatusOK).JSON(profile); err != nil {
		return fmt.Errorf("sending response: %w", err)
	}
	return nil
}
