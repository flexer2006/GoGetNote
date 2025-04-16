package notes

import "errors"

type NoteService interface {
	CreateNote(title, content string, userID string) (*Note, error)
	GetNoteByID(id string) (*Note, error)
	ListNotes() ([]Note, error)
	UpdateNote(id string, title, content string) (*Note, error)
	DeleteNote(id string) error
}

type noteService struct {
	noteRespository NoteRepository
}

func NewNoteService(noteRespository NoteRepository) NoteService {
	return &noteService{
		noteRespository: noteRespository,
	}
}

func (s *noteService) CreateNote(title, content string, userID string) (*Note, error) {
	if title == "" || content == "" {
		return nil, errors.New("title and content cannot be empty")
	}
	note := &Note{
		Title:   title,
		Content: content,
		UserID:  userID,
	}
	createdNote, err := s.noteRespository.Create(note)
	if err != nil {
		return nil, err
	}
	return createdNote, nil
}

func (s *noteService) GetNoteByID(id string) (*Note, error) {
	note, err := s.noteRespository.GetByID(id)
	if err != nil {
		return nil, err
	}
	return note, nil
}

func (s *noteService) ListNotes() ([]Note, error) {
	notes := s.noteRespository.GetAll()
	if len(notes) == 0 {
		return nil, errors.New("no notes found")
	}

	return notes, nil
}

func (s *noteService) UpdateNote(id string, title, content string) (*Note, error) {
	note, err := s.noteRespository.GetByID(id)
	if err != nil {
		return nil, err
	}
	if title != "" {
		note.Title = title
	}
	if content != "" {
		note.Content = content
	}
	updatedNote, err := s.noteRespository.Update(note)
	if err != nil {
		return nil, err
	}
	return updatedNote, nil
}

func (s *noteService) DeleteNote(id string) error {
	err := s.noteRespository.Delete(id)
	if err != nil {
		return err
	}
	return nil
}
