// Package app implements application business logic for the notes service.
package app

import (
	"context"
	"errors"
	"fmt"
	"time"

	"gogetnote/internal/notes/domain/entities"
	"gogetnote/internal/notes/ports/repositories"
	"gogetnote/internal/notes/ports/services"
)

// Ошибки уровня бизнес-логики.
var (
	ErrNotFound      = errors.New("note not found")
	ErrUnauthorized  = errors.New("unauthorized access")
	ErrInvalidParams = errors.New("invalid parameters")
)

// NoteUseCase представляет собой бизнес-логику работы с заметками.
type NoteUseCase struct {
	noteRepo     repositories.NoteRepository
	tokenService services.TokenService
}

// NewNoteUseCase создает новый экземпляр NoteUseCase.
func NewNoteUseCase(noteRepo repositories.NoteRepository, tokenService services.TokenService) *NoteUseCase {
	return &NoteUseCase{
		noteRepo:     noteRepo,
		tokenService: tokenService,
	}
}

// CreateNote создает новую заметку для пользователя.
func (uc *NoteUseCase) CreateNote(ctx context.Context, token, title, content string) (string, error) {
	userID, err := uc.tokenService.ValidateAccessToken(ctx, token)
	if err != nil {
		return "", ErrUnauthorized
	}

	note := entities.NewNote(userID, title, content)
	noteID, err := uc.noteRepo.Create(ctx, note)
	if err != nil {
		return "", fmt.Errorf("failed to create note: %w", err)
	}

	return noteID, nil
}

// GetNote возвращает заметку по ID.
func (uc *NoteUseCase) GetNote(ctx context.Context, token, noteID string) (*entities.Note, error) {
	userID, err := uc.tokenService.ValidateAccessToken(ctx, token)
	if err != nil {
		return nil, ErrUnauthorized
	}

	note, err := uc.noteRepo.GetByID(ctx, noteID, userID)
	if err != nil {
		return nil, fmt.Errorf("failed to get note: %w", err)
	}
	if note == nil {
		return nil, ErrNotFound
	}

	return note, nil
}

// ListNotes возвращает список заметок пользователя с пагинацией.
func (uc *NoteUseCase) ListNotes(ctx context.Context, token string, limit, offset int) ([]*entities.Note, int, error) {
	userID, err := uc.tokenService.ValidateAccessToken(ctx, token)
	if err != nil {
		return nil, 0, ErrUnauthorized
	}

	if limit <= 0 {
		limit = 10
	}
	if offset < 0 {
		offset = 0
	}

	notes, total, err := uc.noteRepo.ListByUserID(ctx, userID, limit, offset)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to list notes: %w", err)
	}

	return notes, total, nil
}

// UpdateNote обновляет существующую заметку.
func (uc *NoteUseCase) UpdateNote(ctx context.Context, token, noteID, title, content string) (*entities.Note, error) {
	userID, err := uc.tokenService.ValidateAccessToken(ctx, token)
	if err != nil {
		return nil, ErrUnauthorized
	}

	note, err := uc.noteRepo.GetByID(ctx, noteID, userID)
	if err != nil {
		return nil, fmt.Errorf("failed to get note: %w", err)
	}
	if note == nil {
		return nil, ErrNotFound
	}

	if title != "" {
		note.Title = title
	}
	if content != "" {
		note.Content = content
	}
	note.UpdatedAt = time.Now()

	if err := uc.noteRepo.Update(ctx, note); err != nil {
		return nil, fmt.Errorf("failed to update note: %w", err)
	}

	return note, nil
}

// DeleteNote удаляет заметку.
func (uc *NoteUseCase) DeleteNote(ctx context.Context, token, noteID string) error {
	userID, err := uc.tokenService.ValidateAccessToken(ctx, token)
	if err != nil {
		return ErrUnauthorized
	}

	note, err := uc.noteRepo.GetByID(ctx, noteID, userID)
	if err != nil {
		return fmt.Errorf("failed to get note: %w", err)
	}
	if note == nil {
		return ErrNotFound
	}

	if err := uc.noteRepo.Delete(ctx, noteID, userID); err != nil {
		return fmt.Errorf("failed to delete note: %w", err)
	}

	return nil
}
