package notes

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
)

// Интерфейс сервиса заметок
type NoteService interface {
	CreateNote(title, content string, userID string) (*Note, error)
	GetNoteByID(id string) (*Note, error)
	ListNotes() ([]Note, error)
	UpdateNote(id string, title, content string) (*Note, error)
	DeleteNote(id string) error
}

// Структура сервиса заметок
type noteService struct {
	noteRespository NoteRepository
	redisClient     *redis.Client
}

// Создание нового сервиса заметок
func NewNoteService(noteRespository NoteRepository, redisClient *redis.Client) NoteService {
	return &noteService{
		noteRespository: noteRespository,
		redisClient:     redisClient,
	}
}

// Метод для создания новой заметки
func (s *noteService) CreateNote(title, content string, userID string) (*Note, error) {
	if title == "" || content == "" {
		return nil, errors.New("title and content cannot be empty")
	}

	// Создаем новую заметку
	note := &Note{
		Title:   title,
		Content: content,
		UserID:  userID,
	}

	// Сохраняем заметку в репозитории
	createdNote, err := s.noteRespository.Create(note)
	if err != nil {
		return nil, err
	}

	// Кешируем данные заметки в Redis с TTL 10 минут
	cacheKey := fmt.Sprintf("%s", createdNote.NoteID)
	err = s.redisClient.Set(context.Background(), cacheKey, createdNote.Content, time.Minute*10).Err()
	if err != nil {
		return nil, err
	}

	return createdNote, nil
}

// Метод для получения заметки по ID с кешированием
func (s *noteService) GetNoteByID(id string) (*Note, error) {
	// Проверяем кеш в Redis
	cacheKey := fmt.Sprintf("%s", id)
	cachedNoteContent, err := s.redisClient.Get(context.Background(), cacheKey).Result()
	if err == nil {
		fmt.Println("From redis cache")
		// Если данные есть в кеше, возвращаем их
		return &Note{
			NoteID:  id,
			Content: cachedNoteContent,
		}, nil
	} else if err != redis.Nil {
		return nil, err
	}

	// Если данных нет в кеше, получаем их из базы данных
	note, err := s.noteRespository.GetByID(id)
	fmt.Print("From database")
	if err != nil {
		return nil, err
	}

	// Кешируем данные в Redis с TTL 10 минут
	err = s.redisClient.Set(context.Background(), cacheKey, note.Content, time.Minute*10).Err()
	if err != nil {
		return nil, err
	}

	return note, nil
}

// Метод для получения всех заметок
func (s *noteService) ListNotes() ([]Note, error) {
	notes := s.noteRespository.GetAll()
	if len(notes) == 0 {
		return nil, errors.New("no notes found")
	}

	// Можно добавить кеширование для всего списка заметок, если нужно
	return notes, nil
}

// Метод для обновления заметки
func (s *noteService) UpdateNote(id string, title, content string) (*Note, error) {
	// Получаем заметку из репозитория
	note, err := s.noteRespository.GetByID(id)
	if err != nil {
		return nil, err
	}

	// Обновляем поля заметки
	if title != "" {
		note.Title = title
	}
	if content != "" {
		note.Content = content
	}

	// Сохраняем обновленную заметку в репозитории
	updatedNote, err := s.noteRespository.Update(note)
	if err != nil {
		return nil, err
	}

	// Обновляем кеш в Redis
	cacheKey := fmt.Sprintf("%s", updatedNote.NoteID)
	err = s.redisClient.Set(context.Background(), cacheKey, updatedNote.Content, time.Minute*10).Err()
	if err != nil {
		return nil, err
	}

	return updatedNote, nil
}

// Метод для удаления заметки
func (s *noteService) DeleteNote(id string) error {
	// Удаляем заметку из репозитория
	err := s.noteRespository.Delete(id)
	if err != nil {
		return err
	}

	// Удаляем заметку из кеша Redis
	cacheKey := fmt.Sprintf("%s", id)
	err = s.redisClient.Del(context.Background(), cacheKey).Err()
	if err != nil {
		return err
	}

	return nil
}
