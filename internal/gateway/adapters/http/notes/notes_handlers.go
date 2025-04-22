// Package notes содержит HTTP-обработчики для управления заметками.
package notes

import (
	"context"
	"errors"
	"fmt"
	"strconv"

	"github.com/gofiber/fiber/v3"
	"go.uber.org/zap"

	"gogetnote/internal/gateway/app/dto"
	"gogetnote/internal/gateway/ports/services"
	"gogetnote/pkg/logger"
)

// Константы ошибок и сообщений для логирования.
const (
	LogHandlerCreateNote = "handling create note request"
	LogHandlerGetNote    = "handling get note request"
	LogHandlerListNotes  = "handling list notes request"
	LogHandlerUpdateNote = "handling update note request"
	LogHandlerDeleteNote = "handling delete note request"

	ErrMsgInvalidNoteID      = "invalid note id"
	ErrMsgInvalidPagination  = "invalid pagination parameters"
	ErrMsgInvalidRequestBody = "invalid request body"
)

// Handler обработчик HTTP-запросов для работы с заметками.
type Handler struct {
	notesService services.NotesService
}

// NewHandler создает новый экземпляр обработчика заметок.
func NewHandler(notesService services.NotesService) *Handler {
	return &Handler{
		notesService: notesService,
	}
}

// CreateNote обрабатывает запрос на создание новой заметки.
func (h *Handler) CreateNote(ctx fiber.Ctx) error {
	userCtx, ok := ctx.Locals("userContext").(context.Context)
	if !ok {
		userCtx = ctx.Context() // Запасной вариант
	}
	log := logger.Log(userCtx).With(zap.String("handler", "Handler.CreateNote"))
	log.Debug(userCtx, LogHandlerCreateNote)

	var req dto.CreateNoteRequest
	if err := ctx.Bind().Body(&req); err != nil {
		log.Error(userCtx, ErrMsgInvalidRequestBody, zap.Error(err))
		if err := ctx.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": ErrMsgInvalidRequestBody,
		}); err != nil {
			return fmt.Errorf("failed to send bad request response: %w", err)
		}
		return nil
	}

	note, err := h.notesService.CreateNote(userCtx, &req)
	if err != nil {
		log.Error(userCtx, "failed to create note", zap.Error(err))
		return handleError(ctx, err)
	}

	if err := ctx.Status(fiber.StatusCreated).JSON(note); err != nil {
		return fmt.Errorf("error sending response: %w", err)
	}
	return nil
}

// GetNote обрабатывает запрос на получение заметки по ID.
func (h *Handler) GetNote(ctx fiber.Ctx) error {
	userCtx, ok := ctx.Locals("userContext").(context.Context)
	if !ok {
		userCtx = ctx.Context() // Запасной вариант
	}
	log := logger.Log(userCtx).With(zap.String("handler", "Handler.GetNote"))
	log.Debug(userCtx, LogHandlerGetNote)

	noteID := ctx.Params("note_id")
	if noteID == "" {
		log.Error(userCtx, ErrMsgInvalidNoteID)
		if err := ctx.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": ErrMsgInvalidNoteID,
		}); err != nil {
			return fmt.Errorf("failed to send bad request response: %w", err)
		}
		return nil
	}

	note, err := h.notesService.GetNote(userCtx, noteID)
	if err != nil {
		log.Error(userCtx, "failed to get note", zap.Error(err))
		return handleError(ctx, err)
	}

	if err := ctx.JSON(note); err != nil {
		return fmt.Errorf("error sending response: %w", err)
	}
	return nil
}

// ListNotes обрабатывает запрос на получение списка заметок с пагинацией.
func (h *Handler) ListNotes(ctx fiber.Ctx) error {
	userCtx, ok := ctx.Locals("userContext").(context.Context)
	if !ok {
		userCtx = ctx.Context() // Запасной вариант
	}
	log := logger.Log(userCtx).With(zap.String("handler", "Handler.ListNotes"))
	log.Debug(userCtx, LogHandlerListNotes)

	// Получаем параметры пагинации
	limitStr := ctx.Query("limit", "10")
	offsetStr := ctx.Query("offset", "0")

	limit, err := strconv.ParseInt(limitStr, 10, 32)
	if err != nil {
		log.Error(userCtx, ErrMsgInvalidPagination, zap.Error(err))
		if err := ctx.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": ErrMsgInvalidPagination,
		}); err != nil {
			return fmt.Errorf("failed to send bad request response: %w", err)
		}
		return nil
	}

	offset, err := strconv.ParseInt(offsetStr, 10, 32)
	if err != nil {
		log.Error(userCtx, ErrMsgInvalidPagination, zap.Error(err))
		if err := ctx.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": ErrMsgInvalidPagination,
		}); err != nil {
			return fmt.Errorf("failed to send bad request response: %w", err)
		}
		return nil
	}

	notes, err := h.notesService.ListNotes(userCtx, int32(limit), int32(offset))
	if err != nil {
		log.Error(userCtx, "failed to list notes", zap.Error(err))
		return handleError(ctx, err)
	}

	if err := ctx.JSON(notes); err != nil {
		return fmt.Errorf("error sending response: %w", err)
	}
	return nil
}

// UpdateNote обрабатывает запрос на обновление заметки.
func (h *Handler) UpdateNote(ctx fiber.Ctx) error {
	userCtx, ok := ctx.Locals("userContext").(context.Context)
	if !ok {
		userCtx = ctx.Context() // Запасной вариант
	}
	log := logger.Log(userCtx).With(zap.String("handler", "Handler.UpdateNote"))
	log.Debug(userCtx, LogHandlerUpdateNote)

	noteID := ctx.Params("note_id")
	if noteID == "" {
		log.Error(userCtx, ErrMsgInvalidNoteID)
		if err := ctx.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": ErrMsgInvalidNoteID,
		}); err != nil {
			return fmt.Errorf("failed to send bad request response: %w", err)
		}
		return nil
	}

	var req dto.UpdateNoteRequest
	if err := ctx.Bind().Body(&req); err != nil {
		log.Error(userCtx, ErrMsgInvalidRequestBody, zap.Error(err))
		if err := ctx.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": ErrMsgInvalidRequestBody,
		}); err != nil {
			return fmt.Errorf("failed to send bad request response: %w", err)
		}
		return nil
	}

	note, err := h.notesService.UpdateNote(userCtx, noteID, &req)
	if err != nil {
		log.Error(userCtx, "failed to update note", zap.Error(err))
		return handleError(ctx, err)
	}

	if err := ctx.JSON(note); err != nil {
		return fmt.Errorf("error sending response: %w", err)
	}
	return nil
}

// DeleteNote обрабатывает запрос на удаление заметки.
func (h *Handler) DeleteNote(ctx fiber.Ctx) error {
	userCtx, ok := ctx.Locals("userContext").(context.Context)
	if !ok {
		userCtx = ctx.Context() // Запасной вариант
	}
	log := logger.Log(userCtx).With(zap.String("handler", "Handler.DeleteNote"))
	log.Debug(userCtx, LogHandlerDeleteNote)

	noteID := ctx.Params("note_id")
	if noteID == "" {
		log.Error(userCtx, ErrMsgInvalidNoteID)
		if err := ctx.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": ErrMsgInvalidNoteID,
		}); err != nil {
			return fmt.Errorf("failed to send bad request response: %w", err)
		}
		return nil
	}

	err := h.notesService.DeleteNote(userCtx, noteID)
	if err != nil {
		log.Error(userCtx, "failed to delete note", zap.Error(err))
		return handleError(ctx, err)
	}

	if err := ctx.SendStatus(fiber.StatusNoContent); err != nil {
		return fmt.Errorf("error sending response: %w", err)
	}
	return nil
}

// handleError обрабатывает ошибки и возвращает соответствующий HTTP-статус.
func handleError(ctx fiber.Ctx, err error) error {
	// В реальном приложении здесь можно добавить более специфичную обработку ошибок
	var fiberErr *fiber.Error
	if errors.As(err, &fiberErr) {
		if err := ctx.Status(fiberErr.Code).JSON(fiber.Map{
			"error": fiberErr.Message,
		}); err != nil {
			return fmt.Errorf("fiber error response error: %w", err)
		}
		return nil
	}

	// По умолчанию возвращаем 500
	if err := ctx.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
		"error": "Internal server error",
	}); err != nil {
		return fmt.Errorf("error sending 500 response: %w", err)
	}
	return nil
}
