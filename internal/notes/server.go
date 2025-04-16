package notes

import (
	"context"
	"fmt"

	notesv1 "gitlab.crja72.ru/golang/2025/spring/course/projects/go9/gogetnote/pkg/api/notes/v1"
	"google.golang.org/protobuf/types/known/emptypb"
)

// noteGRPCServer реализует GRPC сервер для работы с заметками
type noteGRPCServer struct {
	notesv1.UnimplementedNoteServiceServer
	noteService NoteService
}

// NewNoteGRPCServer создает новый экземпляр noteGRPCServer
func NewNoteGRPCServer(noteService NoteService) *noteGRPCServer {
	return &noteGRPCServer{
		noteService: noteService,
	}
}

// CreateNote создает новую заметку
func (s *noteGRPCServer) CreateNote(ctx context.Context, req *notesv1.CreateNoteRequest) (*notesv1.NoteResponse, error) {
	title := req.Title
	if title == "" {
		title = "Untitled"
	}

	content := req.Content
	if content == "" {
		content = "No content"
	}

	// Вызываем метод сервиса
	note, err := s.noteService.CreateNote(title, content, "someuser")
	if err != nil {
		return nil, err
	}

	return &notesv1.NoteResponse{
		Note: &notesv1.Note{
			NoteId:  note.NoteID,
			UserId:  note.UserID,
			Title:   note.Title,
			Content: note.Content,
		},
	}, nil
}

// GetNote получает заметку по ID
func (s *noteGRPCServer) GetNote(ctx context.Context, req *notesv1.GetNoteRequest) (*notesv1.NoteResponse, error) {
	// Получаем заметку
	note, err := s.noteService.GetNoteByID(req.NoteId)
	if err != nil {
		return nil, err
	}

	return &notesv1.NoteResponse{
		Note: &notesv1.Note{
			NoteId:  note.NoteID,
			UserId:  note.UserID,
			Title:   note.Title,
			Content: note.Content,
		},
	}, nil
}

// ListNotes получает список всех заметок
func (s *noteGRPCServer) ListNotes(ctx context.Context, req *notesv1.ListNotesRequest) (*notesv1.ListNotesResponse, error) {
	notes, err := s.noteService.ListNotes()
	if err != nil {
		return nil, err
	}

	var noteResponses []*notesv1.Note
	for _, note := range notes {
		noteResponses = append(noteResponses, &notesv1.Note{
			NoteId:  note.NoteID,
			UserId:  note.UserID,
			Title:   note.Title,
			Content: note.Content,
		})
	}

	return &notesv1.ListNotesResponse{
		Notes: noteResponses,
	}, nil
}

// UpdateNote обновляет существующую заметку
func (s *noteGRPCServer) UpdateNote(ctx context.Context, req *notesv1.UpdateNoteRequest) (*notesv1.NoteResponse, error) {
	// Преобразуем NoteId в uint
	// noteId, err := strconv.ParseUint(req.NoteId, 10, 64)
	// if err != nil {
	// 	return nil, fmt.Errorf("invalid note_id: %v", err)
	// }

	// Преобразуем Title и Content, если они nil
	title := req.Title
	if title == nil {
		*title = ""
	}

	content := req.Content
	if content == nil {
		*content = ""
	}

	// Обновляем заметку
	note, err := s.noteService.UpdateNote(fmt.Sprint(req.NoteId), *title, *content)
	if err != nil {
		return nil, err
	}

	return &notesv1.NoteResponse{
		Note: &notesv1.Note{
			NoteId:  note.NoteID,
			UserId:  note.UserID,
			Title:   note.Title,
			Content: note.Content,
		},
	}, nil
}

// DeleteNote удаляет заметку по ID
func (s *noteGRPCServer) DeleteNote(ctx context.Context, req *notesv1.DeleteNoteRequest) (*emptypb.Empty, error) {
	err := s.noteService.DeleteNote(req.NoteId)
	if err != nil {
		return nil, err
	}
	return &emptypb.Empty{}, nil
}
