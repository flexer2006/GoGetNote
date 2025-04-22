// Package repositories defines repository interfaces for the notes service.
package repositories

import (
	"context"

	"gogetnote/internal/notes/domain/entities"
)

// NoteRepository определяет интерфейс для работы с репозиторием заметок.
type NoteRepository interface {
	Create(ctx context.Context, note *entities.Note) (string, error)
	GetByID(ctx context.Context, noteID, userID string) (*entities.Note, error)
	ListByUserID(ctx context.Context, userID string, limit, offset int) ([]*entities.Note, int, error)
	Update(ctx context.Context, note *entities.Note) error
	Delete(ctx context.Context, noteID, userID string) error
}
