// Package entities defines the domain entities for the notes service.
package entities

import "time"

// Note представляет собой заметку пользователя.
type Note struct {
	ID        string    `json:"id"`
	UserID    string    `json:"user_id"`
	Title     string    `json:"title"`
	Content   string    `json:"content"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// NewNote creates a new note with the given user ID, title, and content.
func NewNote(userID, title, content string) *Note {
	now := time.Now()
	return &Note{
		UserID:    userID,
		Title:     title,
		Content:   content,
		CreatedAt: now,
		UpdatedAt: now,
	}
}
