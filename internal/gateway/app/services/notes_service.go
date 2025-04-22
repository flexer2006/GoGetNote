package services

import (
	"context"
	"fmt"

	"go.uber.org/zap"

	"gogetnote/internal/gateway/app/dto"
	"gogetnote/internal/gateway/ports/cache"
	"gogetnote/internal/gateway/ports/grpc"
	"gogetnote/internal/gateway/ports/services"
	"gogetnote/internal/gateway/resilience"
	notesv1 "gogetnote/pkg/api/notes/v1"
	"gogetnote/pkg/logger"
)

// Константы для логирования.
const (
	LogServiceCreateNote = "notes service: create note"
	LogServiceGetNote    = "notes service: get note"
	LogServiceListNotes  = "notes service: list notes"
	LogServiceUpdateNote = "notes service: update note"
	LogServiceDeleteNote = "notes service: delete note"

	ErrorCreateNoteFailed = "failed to create note"
	ErrorGetNoteFailed    = "failed to get note"
	ErrorListNotesFailed  = "failed to list notes"
	ErrorUpdateNoteFailed = "failed to update note"
	ErrorDeleteNoteFailed = "failed to delete note"
)

// NotesServiceImpl реализация интерфейса NotesService.
type NotesServiceImpl struct {
	notesClient grpc.NotesServiceClient
	cache       cache.Cache
	resilience  *resilience.ServiceResilience
}

// NewNotesService создает новый экземпляр сервиса заметок.
func NewNotesService(notesClient grpc.NotesServiceClient, cache cache.Cache) services.NotesService {
	return &NotesServiceImpl{
		notesClient: notesClient,
		cache:       cache,
		resilience:  resilience.NewServiceResilience("notes-service"),
	}
}

// CreateNote создает новую заметку.
func (s *NotesServiceImpl) CreateNote(ctx context.Context, req *dto.CreateNoteRequest) (*dto.NoteResponse, error) {
	log := logger.Log(ctx)
	log.Info(ctx, LogServiceCreateNote)

	result, err := s.resilience.ExecuteWithResultTokenResponse(ctx, "CreateNote", func() (interface{}, error) {
		response, err := s.notesClient.CreateNote(ctx, req.Title, req.Content)
		if err != nil {
			log.Error(ctx, ErrorCreateNoteFailed, zap.Error(err))
			return nil, fmt.Errorf("%s: %w", ErrorCreateNoteFailed, err)
		}

		return convertNoteResponseFromProto(response), nil
	})

	if err != nil {
		return nil, fmt.Errorf("note creation failed: %w", err)
	}

	return result.(*dto.NoteResponse), nil
}

// GetNote получает заметку по ID.
func (s *NotesServiceImpl) GetNote(ctx context.Context, noteID string) (*dto.NoteResponse, error) {
	log := logger.Log(ctx)
	log.Info(ctx, LogServiceGetNote)

	result, err := s.resilience.ExecuteWithResultTokenResponse(ctx, "GetNote", func() (interface{}, error) {
		response, err := s.notesClient.GetNote(ctx, noteID)
		if err != nil {
			log.Error(ctx, ErrorGetNoteFailed, zap.Error(err))
			return nil, fmt.Errorf("%s: %w", ErrorGetNoteFailed, err)
		}

		return convertNoteResponseFromProto(response), nil
	})

	if err != nil {
		return nil, fmt.Errorf("get note failed: %w", err)
	}

	return result.(*dto.NoteResponse), nil
}

// ListNotes получает список заметок с пагинацией.
func (s *NotesServiceImpl) ListNotes(ctx context.Context, limit, offset int32) (*dto.ListNotesResponse, error) {
	log := logger.Log(ctx)
	log.Info(ctx, LogServiceListNotes)

	result, err := s.resilience.ExecuteWithResultTokenResponse(ctx, "ListNotes", func() (interface{}, error) {
		response, err := s.notesClient.ListNotes(ctx, limit, offset)
		if err != nil {
			log.Error(ctx, ErrorListNotesFailed, zap.Error(err))
			return nil, fmt.Errorf("%s: %w", ErrorListNotesFailed, err)
		}

		return convertListNotesResponseFromProto(response), nil
	})

	if err != nil {
		return nil, fmt.Errorf("list notes failed: %w", err)
	}

	return result.(*dto.ListNotesResponse), nil
}

// UpdateNote обновляет существующую заметку.
func (s *NotesServiceImpl) UpdateNote(ctx context.Context, noteID string, req *dto.UpdateNoteRequest) (*dto.NoteResponse, error) {
	log := logger.Log(ctx)
	log.Info(ctx, LogServiceUpdateNote)

	result, err := s.resilience.ExecuteWithResultTokenResponse(ctx, "UpdateNote", func() (interface{}, error) {
		response, err := s.notesClient.UpdateNote(ctx, noteID, req.Title, req.Content)
		if err != nil {
			log.Error(ctx, ErrorUpdateNoteFailed, zap.Error(err))
			return nil, fmt.Errorf("%s: %w", ErrorUpdateNoteFailed, err)
		}

		return convertNoteResponseFromProto(response), nil
	})

	if err != nil {
		return nil, fmt.Errorf("update note failed: %w", err)
	}

	return result.(*dto.NoteResponse), nil
}

// DeleteNote удаляет заметку.
func (s *NotesServiceImpl) DeleteNote(ctx context.Context, noteID string) error {
	log := logger.Log(ctx)
	log.Info(ctx, LogServiceDeleteNote)

	err := s.resilience.ExecuteWithResilience(ctx, "DeleteNote", func() error {
		err := s.notesClient.DeleteNote(ctx, noteID)
		if err != nil {
			log.Error(ctx, ErrorDeleteNoteFailed, zap.Error(err))
			return fmt.Errorf("%s: %w", ErrorDeleteNoteFailed, err)
		}
		return nil
	})

	if err != nil {
		return fmt.Errorf("delete note failed: %w", err)
	}

	return nil
}

// Вспомогательные функции для конвертации между proto и dto

func convertNoteFromProto(protoNote *notesv1.Note) *dto.Note {
	if protoNote == nil {
		return nil
	}
	return &dto.Note{
		ID:        protoNote.NoteId,
		UserID:    protoNote.UserId,
		Title:     protoNote.Title,
		Content:   protoNote.Content,
		CreatedAt: protoNote.CreatedAt.AsTime(),
		UpdatedAt: protoNote.UpdatedAt.AsTime(),
	}
}

func convertNoteResponseFromProto(protoResp *notesv1.NoteResponse) *dto.NoteResponse {
	if protoResp == nil {
		return nil
	}
	return &dto.NoteResponse{
		Note: convertNoteFromProto(protoResp.Note),
	}
}

func convertListNotesResponseFromProto(protoResp *notesv1.ListNotesResponse) *dto.ListNotesResponse {
	if protoResp == nil {
		return nil
	}

	notes := make([]*dto.Note, len(protoResp.Notes))
	for i, note := range protoResp.Notes {
		notes[i] = convertNoteFromProto(note)
	}

	return &dto.ListNotesResponse{
		Notes:      notes,
		TotalCount: protoResp.TotalCount,
		Offset:     protoResp.Offset,
		Limit:      protoResp.Limit,
	}
}
