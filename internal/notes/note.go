// Package notes using for domain
package notes

import (
	"time"
)

// Note структура для хранения заметок.
type Note struct {
	NoteID    string    `gorm:"primaryKey;type:varchar(100);unique_index" json:"note_id"`
	UserID    string    `gorm:"type:varchar(100)" json:"user_id"`
	Title     string    `gorm:"type:varchar(255)" json:"title"`
	Content   string    `gorm:"type:text" json:"content"`
	CreatedAt time.Time `gorm:"default:CURRENT_TIMESTAMP" json:"created_at"`
	UpdatedAt time.Time `gorm:"default:CURRENT_TIMESTAMP" json:"updated_at"`
}
