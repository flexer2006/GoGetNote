package notes

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
)

// NoteService defines methods for handling notes
type NoteService interface {
	CreateNote(title, content string, userID string) (*Note, error)
	GetNoteByID(id string) (*Note, error)
	ListNotes() ([]Note, error)
	UpdateNote(id string, title, content string) (*Note, error)
	DeleteNote(id string) error
}

// noteService struct implements NoteService
type noteService struct {
	noteRespository NoteRepository
	redisClient     *redis.Client
}

// NewNoteService creates a new note service
func NewNoteService(noteRespository NoteRepository, redisClient *redis.Client) NoteService {
	return &noteService{
		noteRespository: noteRespository,
		redisClient:     redisClient,
	}
}

// CreateNote creates a new note and stores it in the repository and cache
func (s *noteService) CreateNote(title, content string, userID string) (*Note, error) {
	if title == "" || content == "" {
		return nil, fmt.Errorf("title and content cannot be empty")
	}

	note := &Note{
		Title:   title,
		Content: content,
		UserID:  userID,
	}

	createdNote, err := s.noteRespository.Create(note)
	if err != nil {
		return nil, fmt.Errorf("failed to create note: %w", err)
	}

	cacheKey := createdNote.NoteID
	err = s.redisClient.Set(context.Background(), cacheKey, createdNote.Content, time.Minute*10).Err()
	if err != nil {
		return nil, fmt.Errorf("failed to cache note: %w", err)
	}

	return createdNote, nil
}

// GetNoteByID retrieves a note by its ID, first checking the cache
func (s *noteService) GetNoteByID(id string) (*Note, error) {
	cacheKey := id
	cachedNoteContent, err := s.redisClient.Get(context.Background(), cacheKey).Result()
	if err == nil {
		fmt.Println("From redis cache")
		return &Note{
			NoteID:  id,
			Content: cachedNoteContent,
		}, nil
	} else if !errors.Is(err, redis.Nil) {
		return nil, fmt.Errorf("failed to retrieve from cache: %w", err)
	}

	note, err := s.noteRespository.GetByID(id)
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve from database: %w", err)
	}

	err = s.redisClient.Set(context.Background(), cacheKey, note.Content, time.Minute*10).Err()
	if err != nil {
		return nil, fmt.Errorf("failed to cache note: %w", err)
	}

	return note, nil
}

// ListNotes retrieves all notes
func (s *noteService) ListNotes() ([]Note, error) {
	notes := s.noteRespository.GetAll()
	if len(notes) == 0 {
		return nil, fmt.Errorf("no notes found")
	}

	return notes, nil
}

// UpdateNote updates an existing note
func (s *noteService) UpdateNote(id string, title, content string) (*Note, error) {
	note, err := s.noteRespository.GetByID(id)
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve note: %w", err)
	}

	if title != "" {
		note.Title = title
	}
	if content != "" {
		note.Content = content
	}

	updatedNote, err := s.noteRespository.Update(note)
	if err != nil {
		return nil, fmt.Errorf("failed to update note: %w", err)
	}

	cacheKey := updatedNote.NoteID
	err = s.redisClient.Set(context.Background(), cacheKey, updatedNote.Content, time.Minute*10).Err()
	if err != nil {
		return nil, fmt.Errorf("failed to cache updated note: %w", err)
	}

	return updatedNote, nil
}

// DeleteNote deletes a note from repository and cache
func (s *noteService) DeleteNote(id string) error {
	err := s.noteRespository.Delete(id)
	if err != nil {
		return fmt.Errorf("failed to delete note: %w", err)
	}

	cacheKey := id
	err = s.redisClient.Del(context.Background(), cacheKey).Err()
	if err != nil {
		return fmt.Errorf("failed to delete from cache: %w", err)
	}

	return nil
}
