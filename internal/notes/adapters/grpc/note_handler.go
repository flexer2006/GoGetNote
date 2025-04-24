// Package grpc provides gRPC handlers for the notes service.
package grpc

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"go.uber.org/zap"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"
	"google.golang.org/protobuf/types/known/timestamppb"

	"gogetnote/internal/notes/app"
	"gogetnote/internal/notes/domain/entities"
	notesv1 "gogetnote/pkg/api/notes/v1"
	"gogetnote/pkg/logger"
)

// Add these static error definitions at the package level.
var (
	ErrMetadataNotFound   = errors.New("metadata not found in context")
	ErrAuthHeaderNotFound = errors.New("authorization header not found")
	ErrInvalidAuthFormat  = errors.New("invalid authorization header format")
)

// wrapGrpcError wraps a gRPC status error for consistent error handling.
func wrapGrpcError(code codes.Code, message string) error {
	return fmt.Errorf("gRPC error: %w", status.Error(code, message))
}

type NoteUseCase interface {
	CreateNote(ctx context.Context, token, title, content string) (string, error)
	GetNote(ctx context.Context, token, noteID string) (*entities.Note, error)
	ListNotes(ctx context.Context, token string, limit, offset int) ([]*entities.Note, int, error)
	UpdateNote(ctx context.Context, token, noteID, title, content string) (*entities.Note, error)
	DeleteNote(ctx context.Context, token, noteID string) error
}

// NoteHandler обрабатывает gRPC запросы к сервису заметок.
type NoteHandler struct {
	noteUseCase NoteUseCase
	notesv1.UnimplementedNoteServiceServer
}

// NewNoteHandler создает новый обработчик gRPC запросов к сервису заметок.
func NewNoteHandler(noteUseCase NoteUseCase) *NoteHandler {
	return &NoteHandler{
		noteUseCase: noteUseCase,
	}
}

func ExtractToken(ctx context.Context) (string, error) {
	mtd, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return "", ErrMetadataNotFound
	}

	// Отладочный вывод всех метаданных
	logger.Log(ctx).Debug(ctx, "Received metadata", zap.Any("metadata", mtd))

	values := mtd.Get("authorization")
	if len(values) == 0 {
		return "", ErrAuthHeaderNotFound
	}

	authHeader := values[0]
	logger.Log(ctx).Debug(ctx, "Received authorization header", zap.String("auth_header", authHeader))

	// Более гибкий парсинг токена
	if strings.HasPrefix(authHeader, "Bearer ") {
		return authHeader[7:], nil
	}

	// Если префикса нет, но есть токен, используем его напрямую
	return authHeader, nil
}

// CreateNote создает новую заметку.
func (h *NoteHandler) CreateNote(ctx context.Context, req *notesv1.CreateNoteRequest) (*notesv1.NoteResponse, error) {
	log := logger.Log(ctx).With(zap.String("handler", "NoteHandler.CreateNote"))
	log.Debug(ctx, "create note request received")

	token, err := ExtractToken(ctx)
	if err != nil {
		log.Error(ctx, "failed to extract token", zap.Error(err))
		return nil, wrapGrpcError(codes.Unauthenticated, "authentication required")
	}

	noteID, err := h.noteUseCase.CreateNote(ctx, token, req.GetTitle(), req.GetContent())
	if err != nil {
		log.Error(ctx, "failed to create note", zap.Error(err))

		if errors.Is(err, app.ErrUnauthorized) {
			return nil, wrapGrpcError(codes.Unauthenticated, "invalid or expired token")
		}

		return nil, wrapGrpcError(codes.Internal, "failed to create note")
	}

	// Получаем созданную заметку для ответа
	note, err := h.noteUseCase.GetNote(ctx, token, noteID)
	if err != nil {
		log.Error(ctx, "failed to get created note", zap.Error(err))
		return nil, wrapGrpcError(codes.Internal, "note was created but could not be retrieved")
	}

	return &notesv1.NoteResponse{
		Note: &notesv1.Note{
			NoteId:    note.ID,
			UserId:    note.UserID,
			Title:     note.Title,
			Content:   note.Content,
			CreatedAt: timestamppb.New(note.CreatedAt),
			UpdatedAt: timestamppb.New(note.UpdatedAt),
		},
	}, nil
}

// GetNote получает заметку по ID.
func (h *NoteHandler) GetNote(ctx context.Context, req *notesv1.GetNoteRequest) (*notesv1.NoteResponse, error) {
	log := logger.Log(ctx).With(zap.String("handler", "NoteHandler.GetNote"))
	log.Debug(ctx, "get note request received", zap.String("noteID", req.GetNoteId()))

	token, err := ExtractToken(ctx)
	if err != nil {
		log.Error(ctx, "failed to extract token", zap.Error(err))
		return nil, wrapGrpcError(codes.Unauthenticated, "authentication required")
	}

	note, err := h.noteUseCase.GetNote(ctx, token, req.GetNoteId())
	if err != nil {
		log.Error(ctx, "failed to get note", zap.Error(err))

		switch {
		case errors.Is(err, app.ErrUnauthorized):
			return nil, wrapGrpcError(codes.Unauthenticated, "invalid or expired token")
		case errors.Is(err, app.ErrNotFound):
			return nil, wrapGrpcError(codes.NotFound, "note not found")
		default:
			return nil, wrapGrpcError(codes.Internal, "failed to get note")
		}
	}

	return &notesv1.NoteResponse{
		Note: &notesv1.Note{
			NoteId:    note.ID,
			UserId:    note.UserID,
			Title:     note.Title,
			Content:   note.Content,
			CreatedAt: timestamppb.New(note.CreatedAt),
			UpdatedAt: timestamppb.New(note.UpdatedAt),
		},
	}, nil
}

// ListNotes получает список заметок с пагинацией.
func (h *NoteHandler) ListNotes(ctx context.Context, req *notesv1.ListNotesRequest) (*notesv1.ListNotesResponse, error) {
	log := logger.Log(ctx).With(zap.String("handler", "NoteHandler.ListNotes"))
	log.Debug(ctx, "list notes request received",
		zap.Int32("limit", req.GetLimit()),
		zap.Int32("offset", req.GetOffset()))

	token, err := ExtractToken(ctx)
	if err != nil {
		log.Error(ctx, "failed to extract token", zap.Error(err))
		return nil, wrapGrpcError(codes.Unauthenticated, "authentication required")
	}

	notes, total, err := h.noteUseCase.ListNotes(ctx, token, int(req.GetLimit()), int(req.GetOffset()))
	if err != nil {
		log.Error(ctx, "failed to list notes", zap.Error(err))

		if errors.Is(err, app.ErrUnauthorized) {
			return nil, wrapGrpcError(codes.Unauthenticated, "invalid or expired token")
		}

		return nil, wrapGrpcError(codes.Internal, "failed to list notes")
	}

	noteResponses := make([]*notesv1.Note, 0, len(notes))
	for _, note := range notes {
		noteResponses = append(noteResponses, &notesv1.Note{
			NoteId:    note.ID,
			UserId:    note.UserID,
			Title:     note.Title,
			Content:   note.Content,
			CreatedAt: timestamppb.New(note.CreatedAt),
			UpdatedAt: timestamppb.New(note.UpdatedAt),
		})
	}

	// Add a check for potential overflow
	var totalCount int32
	switch {
	case total <= 0:
		totalCount = 0
	case total > 2147483647: // Max int32 value (2^31-1)
		totalCount = 2147483647 // Max int32 value
	default:
		totalCount = int32(total) //nolint:gosec // We've already checked the bounds
	}

	return &notesv1.ListNotesResponse{
		Notes:      noteResponses,
		TotalCount: totalCount,
		Offset:     req.GetOffset(),
		Limit:      req.GetLimit(),
	}, nil
}

// UpdateNote обновляет существующую заметку.
func (h *NoteHandler) UpdateNote(ctx context.Context, req *notesv1.UpdateNoteRequest) (*notesv1.NoteResponse, error) {
	log := logger.Log(ctx).With(zap.String("handler", "NoteHandler.UpdateNote"))
	log.Debug(ctx, "update note request received", zap.String("noteID", req.GetNoteId()))

	token, err := ExtractToken(ctx)
	if err != nil {
		log.Error(ctx, "failed to extract token", zap.Error(err))
		return nil, wrapGrpcError(codes.Unauthenticated, "authentication required")
	}

	var title, content string
	if req.Title != nil {
		title = *req.Title
	}
	if req.Content != nil {
		content = *req.Content
	}

	note, err := h.noteUseCase.UpdateNote(ctx, token, req.GetNoteId(), title, content)
	if err != nil {
		log.Error(ctx, "failed to update note", zap.Error(err))

		switch {
		case errors.Is(err, app.ErrUnauthorized):
			return nil, wrapGrpcError(codes.Unauthenticated, "invalid or expired token")
		case errors.Is(err, app.ErrNotFound):
			return nil, wrapGrpcError(codes.NotFound, "note not found")
		default:
			return nil, wrapGrpcError(codes.Internal, "failed to update note")
		}
	}

	return &notesv1.NoteResponse{
		Note: &notesv1.Note{
			NoteId:    note.ID,
			UserId:    note.UserID,
			Title:     note.Title,
			Content:   note.Content,
			CreatedAt: timestamppb.New(note.CreatedAt),
			UpdatedAt: timestamppb.New(note.UpdatedAt),
		},
	}, nil
}

// DeleteNote удаляет заметку.
func (h *NoteHandler) DeleteNote(ctx context.Context, req *notesv1.DeleteNoteRequest) (*emptypb.Empty, error) {
	log := logger.Log(ctx).With(zap.String("handler", "NoteHandler.DeleteNote"))
	log.Debug(ctx, "delete note request received", zap.String("noteID", req.GetNoteId()))

	token, err := ExtractToken(ctx)
	if err != nil {
		log.Error(ctx, "failed to extract token", zap.Error(err))
		return nil, wrapGrpcError(codes.Unauthenticated, "authentication required")
	}

	err = h.noteUseCase.DeleteNote(ctx, token, req.GetNoteId())
	if err != nil {
		log.Error(ctx, "failed to delete note", zap.Error(err))

		switch {
		case errors.Is(err, app.ErrUnauthorized):
			return nil, wrapGrpcError(codes.Unauthenticated, "invalid or expired token")
		case errors.Is(err, app.ErrNotFound):
			return nil, wrapGrpcError(codes.NotFound, "note not found")
		default:
			return nil, wrapGrpcError(codes.Internal, "failed to delete note")
		}
	}

	return &emptypb.Empty{}, nil
}
