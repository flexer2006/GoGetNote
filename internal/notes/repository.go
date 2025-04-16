package notes

import (
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

type NoteRepository interface {
	Create(note *Note) (*Note, error)
	GetByID(id string) (*Note, error)
	GetAll() []Note	
	Update(note *Note) (*Note, error)
	Delete(id string) error
}

type noteRepository struct {
	db *gorm.DB
}

func NewNoteRepository(db *gorm.DB) NoteRepository {
	return &noteRepository{
		db: db,
	}
}

func (repo *noteRepository) Create(note *Note) (*Note, error) {
	if err := repo.db.Table("notes").Create(note).Error; err != nil {
		return nil, err
	}
	return note, nil
}

func (repo *noteRepository) GetByID(id string) (*Note, error) {
	var note Note
	if err := repo.db.Table("notes").Where("id = ?", id).First(&note).Error; err != nil {
		return nil, err
	}
	return &note, nil
}

func (repo *noteRepository) GetAll() []Note {
	var notes []Note
	// if err := repo.db.Table("notes").Find(&notes).Error; err != nil {
	// 	return nil, err
	// }
	repo.db.
		Table("notes").
		Where("deleted_at is null").
		Order("id asc").
		Scan(&notes)
	return notes
}

func (repo *noteRepository) Update(note *Note) (*Note, error) {
	result := repo.db.Clauses(clause.Returning{}).Updates(note)
	if result.Error != nil {
		return nil, result.Error
	}
	return note, nil
}

func (repo *noteRepository) Delete(id string) error {
	result := repo.db.Delete(&Note{}, id)
	if result.Error != nil {
		return result.Error
	}
	return nil
}