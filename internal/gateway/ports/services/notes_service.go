package services

import (
	"context"

	"gogetnote/internal/gateway/app/dto"
)

// NotesService определяет интерфейс для работы с сервисом заметок.
type NotesService interface {
	// CreateNote создает новую заметку
	CreateNote(ctx context.Context, req *dto.CreateNoteRequest) (*dto.NoteResponse, error)

	// GetNote получает заметку по ID
	GetNote(ctx context.Context, noteID string) (*dto.NoteResponse, error)

	// ListNotes получает список заметок с пагинацией
	ListNotes(ctx context.Context, limit, offset int32) (*dto.ListNotesResponse, error)

	// UpdateNote обновляет существующую заметку
	UpdateNote(ctx context.Context, noteID string, req *dto.UpdateNoteRequest) (*dto.NoteResponse, error)

	// DeleteNote удаляет заметку
	DeleteNote(ctx context.Context, noteID string) error
}
