package dto

import (
	"time"
)

// CreateNoteRequest содержит данные для создания заметки.
type CreateNoteRequest struct {
	Title   string `json:"title" validate:"required"`
	Content string `json:"content" validate:"required"`
}

// UpdateNoteRequest содержит данные для обновления заметки.
type UpdateNoteRequest struct {
	Title   *string `json:"title"`
	Content *string `json:"content"`
}

// Note представляет заметку.
type Note struct {
	ID        string    `json:"id"`
	UserID    string    `json:"user_id"`
	Title     string    `json:"title"`
	Content   string    `json:"content"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// NoteResponse содержит информацию о заметке для ответа.
type NoteResponse struct {
	Note *Note `json:"note"`
}

// ListNotesResponse содержит список заметок и информацию о пагинации.
type ListNotesResponse struct {
	Notes      []*Note `json:"notes"`
	TotalCount int32   `json:"total_count"`
	Offset     int32   `json:"offset"`
	Limit      int32   `json:"limit"`
}
