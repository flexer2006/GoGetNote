package grpc

import (
	"context"

	notesv1 "gogetnote/pkg/api/notes/v1"
)

// NotesServiceClient определяет интерфейс для взаимодействия с сервисом заметок.
type NotesServiceClient interface {
	CreateNote(ctx context.Context, title, content string) (*notesv1.NoteResponse, error)

	GetNote(ctx context.Context, noteID string) (*notesv1.NoteResponse, error)

	ListNotes(ctx context.Context, limit, offset int32) (*notesv1.ListNotesResponse, error)

	UpdateNote(ctx context.Context, noteID string, title, content *string) (*notesv1.NoteResponse, error)

	DeleteNote(ctx context.Context, noteID string) error

	Close() error
}
