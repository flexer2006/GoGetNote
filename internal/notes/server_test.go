package notes

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"

	notesv1 "gitlab.crja72.ru/golang/2025/spring/course/projects/go9/gogetnote/pkg/api/notes/v1"
)

// Мок-сервис для NoteService
type MockNoteService struct {
	mock.Mock
}

func (m *MockNoteService) CreateNote(title, content, userID string) (*Note, error) {
	args := m.Called(title, content, userID)
	return args.Get(0).(*Note), args.Error(1)
}

func (m *MockNoteService) GetNoteByID(id string) (*Note, error) {
	args := m.Called(id)
	return args.Get(0).(*Note), args.Error(1)
}

func (m *MockNoteService) ListNotes() ([]Note, error) {
	args := m.Called()
	return args.Get(0).([]Note), args.Error(1)
}

func (m *MockNoteService) UpdateNote(id, title, content string) (*Note, error) {
	args := m.Called(id, title, content)
	return args.Get(0).(*Note), args.Error(1)
}

func (m *MockNoteService) DeleteNote(id string) error {
	args := m.Called(id)
	return args.Error(0)
}

func TestCreateNote(t *testing.T) {
	mockNoteService := new(MockNoteService)
	server := NewNoteGRPCServer(mockNoteService)

	// Мокаем поведение сервиса
	mockNoteService.On("CreateNote", "Test Title", "Test Content", "someuser").Return(&Note{
		NoteID:  "123",
		UserID:  "someuser",
		Title:   "Test Title",
		Content: "Test Content",
	}, nil)

	// Подготавливаем запрос
	req := &notesv1.CreateNoteRequest{
		Title:   "Test Title",
		Content: "Test Content",
	}

	// Вызов метода
	resp, err := server.CreateNote(context.Background(), req)

	// Проверяем результаты
	assert.NoError(t, err)
	assert.NotNil(t, resp)
	assert.Equal(t, "123", resp.Note.NoteId)
	assert.Equal(t, "Test Title", resp.Note.Title)
	assert.Equal(t, "Test Content", resp.Note.Content)

	// Проверяем, что метод был вызван с нужными аргументами
	mockNoteService.AssertExpectations(t)
}

func TestGetNote(t *testing.T) {
	mockNoteService := new(MockNoteService)
	server := NewNoteGRPCServer(mockNoteService)

	// Мокаем поведение сервиса
	mockNoteService.On("GetNoteByID", "123").Return(&Note{
		NoteID:  "123",
		UserID:  "someuser",
		Title:   "Test Title",
		Content: "Test Content",
	}, nil)

	// Подготавливаем запрос
	req := &notesv1.GetNoteRequest{
		NoteId: "123",
	}

	// Вызов метода
	resp, err := server.GetNote(context.Background(), req)

	// Проверяем результаты
	assert.NoError(t, err)
	assert.NotNil(t, resp)
	assert.Equal(t, "123", resp.Note.NoteId)
	assert.Equal(t, "Test Title", resp.Note.Title)
	assert.Equal(t, "Test Content", resp.Note.Content)

	// Проверяем, что метод был вызван с нужными аргументами
	mockNoteService.AssertExpectations(t)
}

func TestListNotes(t *testing.T) {
	mockNoteService := new(MockNoteService)
	server := NewNoteGRPCServer(mockNoteService)

	// Мокаем поведение сервиса
	mockNoteService.On("ListNotes").Return([]Note{
		{NoteID: "123", Title: "Note 1", Content: "Content 1", UserID: "user1"},
		{NoteID: "124", Title: "Note 2", Content: "Content 2", UserID: "user2"},
	}, nil)

	// Подготавливаем запрос
	req := &notesv1.ListNotesRequest{}

	// Вызов метода
	resp, err := server.ListNotes(context.Background(), req)

	// Проверяем результаты
	assert.NoError(t, err)
	assert.Len(t, resp.Notes, 2)
	assert.Equal(t, "123", resp.Notes[0].NoteId)
	assert.Equal(t, "Note 1", resp.Notes[0].Title)

	// Проверяем, что метод был вызван с нужными аргументами
	mockNoteService.AssertExpectations(t)
}

func TestUpdateNote(t *testing.T) {
	mockNoteService := new(MockNoteService)
	server := NewNoteGRPCServer(mockNoteService)

	// Мокаем поведение сервиса
	mockNoteService.On("UpdateNote", "123", "Updated Title", "Updated Content").Return(&Note{
		NoteID:  "123",
		UserID:  "someuser",
		Title:   "Updated Title",
		Content: "Updated Content",
	}, nil)

	// Подготавливаем запрос
	req := &notesv1.UpdateNoteRequest{
		NoteId:  "123",
		Title:   stringPtr("Updated Title"),
		Content: stringPtr("Updated Content"),
	}

	// Вызов метода
	resp, err := server.UpdateNote(context.Background(), req)

	// Проверяем результаты
	assert.NoError(t, err)
	assert.NotNil(t, resp)
	assert.Equal(t, "123", resp.Note.NoteId)
	assert.Equal(t, "Updated Title", resp.Note.Title)
	assert.Equal(t, "Updated Content", resp.Note.Content)

	// Проверяем, что метод был вызван с нужными аргументами
	mockNoteService.AssertExpectations(t)
}

func TestDeleteNote(t *testing.T) {
	mockNoteService := new(MockNoteService)
	server := NewNoteGRPCServer(mockNoteService)

	// Мокаем поведение сервиса
	mockNoteService.On("DeleteNote", "123").Return(nil)

	// Подготавливаем запрос
	req := &notesv1.DeleteNoteRequest{
		NoteId: "123",
	}

	// Вызов метода
	resp, err := server.DeleteNote(context.Background(), req)

	// Проверяем результаты
	assert.NoError(t, err)
	assert.NotNil(t, resp)

	// Проверяем, что метод был вызван с нужными аргументами
	mockNoteService.AssertExpectations(t)
}

func stringPtr(s string) *string {
	return &s
}
