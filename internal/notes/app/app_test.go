package app_test

import (
	"context"
	"errors"
	"gogetnote/internal/notes/app"
	"gogetnote/internal/notes/domain/entities"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

var (
	ErrDatabaseOperation = errors.New("database error")
	ErrTokenInvalid      = errors.New("invalid token")
)

type mockNoteRepository struct {
	mock.Mock
}

func (m *mockNoteRepository) Create(ctx context.Context, note *entities.Note) (string, error) {
	args := m.Called(ctx, note)
	return args.String(0), args.Error(1)
}

func (m *mockNoteRepository) GetByID(ctx context.Context, id string, userID string) (*entities.Note, error) {
	args := m.Called(ctx, id, userID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*entities.Note), args.Error(1)
}

func (m *mockNoteRepository) ListByUserID(ctx context.Context, userID string, limit, offset int) ([]*entities.Note, int, error) {
	args := m.Called(ctx, userID, limit, offset)
	return args.Get(0).([]*entities.Note), args.Int(1), args.Error(2)
}

func (m *mockNoteRepository) Update(ctx context.Context, note *entities.Note) error {
	return m.Called(ctx, note).Error(0)
}

func (m *mockNoteRepository) Delete(ctx context.Context, id string, userID string) error {
	return m.Called(ctx, id, userID).Error(0)
}

type mockTokenService struct {
	mock.Mock
}

func (m *mockTokenService) ValidateAccessToken(ctx context.Context, token string) (string, error) {
	args := m.Called(ctx, token)
	return args.String(0), args.Error(1)
}

func TestNewNoteUseCase(t *testing.T) {
	mockRepo := new(mockNoteRepository)
	mockTokenSvc := new(mockTokenService)

	useCase := app.NewNoteUseCase(mockRepo, mockTokenSvc)

	assert.NotNil(t, useCase, "NewNoteUseCase should return a non-nil object")
}

func TestCreateNote(t *testing.T) {
	userID := "test-user-id"
	token := "valid-token"
	title := "Test Note"
	content := "This is a test note content"
	noteID := "note-123"

	tests := []struct {
		name           string
		token          string
		title          string
		content        string
		setupMocks     func(mockRepo *mockNoteRepository, mockTokenSvc *mockTokenService)
		expectedID     string
		expectedErrMsg string
		expectedErr    error
	}{
		{
			name:    "success - note created",
			token:   token,
			title:   title,
			content: content,
			setupMocks: func(mockRepo *mockNoteRepository, mockTokenSvc *mockTokenService) {
				mockTokenSvc.On("ValidateAccessToken", mock.Anything, token).Return(userID, nil).Once()

				mockRepo.On("Create", mock.Anything, mock.MatchedBy(func(n *entities.Note) bool {
					return n.UserID == userID && n.Title == title && n.Content == content
				})).Return(noteID, nil).Once()
			},
			expectedID:  noteID,
			expectedErr: nil,
		},
		{
			name:    "error - invalid token",
			token:   "invalid-token",
			title:   title,
			content: content,
			setupMocks: func(mockRepo *mockNoteRepository, mockTokenSvc *mockTokenService) {
				mockTokenSvc.On("ValidateAccessToken", mock.Anything, "invalid-token").
					Return("", ErrTokenInvalid).Once()
			},
			expectedID:     "",
			expectedErrMsg: "unauthorized access",
			expectedErr:    app.ErrUnauthorized,
		},
		{
			name:    "error - repository error",
			token:   token,
			title:   title,
			content: content,
			setupMocks: func(mockRepo *mockNoteRepository, mockTokenSvc *mockTokenService) {
				mockTokenSvc.On("ValidateAccessToken", mock.Anything, token).Return(userID, nil).Once()

				mockRepo.On("Create", mock.Anything, mock.Anything).
					Return("", ErrDatabaseOperation).Once()
			},
			expectedID:     "",
			expectedErrMsg: "failed to create note",
			expectedErr:    ErrDatabaseOperation,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockRepo := new(mockNoteRepository)
			mockTokenSvc := new(mockTokenService)

			tt.setupMocks(mockRepo, mockTokenSvc)

			useCase := app.NewNoteUseCase(mockRepo, mockTokenSvc)
			ctx := context.Background()

			id, err := useCase.CreateNote(ctx, tt.token, tt.title, tt.content)

			if tt.expectedErr != nil {
				require.Error(t, err)
				if tt.expectedErr == app.ErrUnauthorized {
					assert.ErrorIs(t, err, app.ErrUnauthorized)
				} else {
					assert.ErrorContains(t, err, tt.expectedErrMsg)
				}
				assert.Empty(t, id)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tt.expectedID, id)
			}

			mockRepo.AssertExpectations(t)
			mockTokenSvc.AssertExpectations(t)
		})
	}
}

func TestGetNote(t *testing.T) {
	userID := "test-user-id"
	token := "valid-token"
	noteID := "note-123"
	now := time.Now()

	testNote := &entities.Note{
		ID:        noteID,
		UserID:    userID,
		Title:     "Test Note",
		Content:   "This is a test note content",
		CreatedAt: now.Add(-time.Hour),
		UpdatedAt: now,
	}

	tests := []struct {
		name           string
		token          string
		noteID         string
		setupMocks     func(mockRepo *mockNoteRepository, mockTokenSvc *mockTokenService)
		expectedNote   *entities.Note
		expectedErrMsg string
		expectedErr    error
	}{
		{
			name:   "success - note found",
			token:  token,
			noteID: noteID,
			setupMocks: func(mockRepo *mockNoteRepository, mockTokenSvc *mockTokenService) {
				mockTokenSvc.On("ValidateAccessToken", mock.Anything, token).Return(userID, nil).Once()
				mockRepo.On("GetByID", mock.Anything, noteID, userID).Return(testNote, nil).Once()
			},
			expectedNote: testNote,
			expectedErr:  nil,
		},
		{
			name:   "error - invalid token",
			token:  "invalid-token",
			noteID: noteID,
			setupMocks: func(mockRepo *mockNoteRepository, mockTokenSvc *mockTokenService) {
				mockTokenSvc.On("ValidateAccessToken", mock.Anything, "invalid-token").
					Return("", ErrTokenInvalid).Once()
			},
			expectedNote:   nil,
			expectedErrMsg: "unauthorized access",
			expectedErr:    app.ErrUnauthorized,
		},
		{
			name:   "error - note not found",
			token:  token,
			noteID: "nonexistent-note",
			setupMocks: func(mockRepo *mockNoteRepository, mockTokenSvc *mockTokenService) {
				mockTokenSvc.On("ValidateAccessToken", mock.Anything, token).Return(userID, nil).Once()
				mockRepo.On("GetByID", mock.Anything, "nonexistent-note", userID).Return(nil, nil).Once()
			},
			expectedNote:   nil,
			expectedErrMsg: "note not found",
			expectedErr:    app.ErrNotFound,
		},
		{
			name:   "error - database error",
			token:  token,
			noteID: noteID,
			setupMocks: func(mockRepo *mockNoteRepository, mockTokenSvc *mockTokenService) {
				mockTokenSvc.On("ValidateAccessToken", mock.Anything, token).Return(userID, nil).Once()
				mockRepo.On("GetByID", mock.Anything, noteID, userID).Return(nil, ErrDatabaseOperation).Once()
			},
			expectedNote:   nil,
			expectedErrMsg: "failed to get note",
			expectedErr:    ErrDatabaseOperation,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockRepo := new(mockNoteRepository)
			mockTokenSvc := new(mockTokenService)

			tt.setupMocks(mockRepo, mockTokenSvc)

			useCase := app.NewNoteUseCase(mockRepo, mockTokenSvc)
			ctx := context.Background()

			note, err := useCase.GetNote(ctx, tt.token, tt.noteID)

			if tt.expectedErr != nil {
				require.Error(t, err)
				if errors.Is(tt.expectedErr, app.ErrUnauthorized) || errors.Is(tt.expectedErr, app.ErrNotFound) {
					assert.ErrorIs(t, err, tt.expectedErr)
				} else {
					assert.ErrorContains(t, err, tt.expectedErrMsg)
				}
				assert.Nil(t, note)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tt.expectedNote, note)
			}

			mockRepo.AssertExpectations(t)
			mockTokenSvc.AssertExpectations(t)
		})
	}
}

func TestDeleteNote(t *testing.T) {
	userID := "test-user-id"
	token := "valid-token"
	noteID := "note-123"
	now := time.Now()

	testNote := &entities.Note{
		ID:        noteID,
		UserID:    userID,
		Title:     "Test Note",
		Content:   "This is a test note content",
		CreatedAt: now.Add(-time.Hour),
		UpdatedAt: now,
	}

	tests := []struct {
		name           string
		token          string
		noteID         string
		setupMocks     func(mockRepo *mockNoteRepository, mockTokenSvc *mockTokenService)
		expectedErrMsg string
		expectedErr    error
	}{
		{
			name:   "success - note deleted",
			token:  token,
			noteID: noteID,
			setupMocks: func(mockRepo *mockNoteRepository, mockTokenSvc *mockTokenService) {
				mockTokenSvc.On("ValidateAccessToken", mock.Anything, token).Return(userID, nil).Once()
				mockRepo.On("GetByID", mock.Anything, noteID, userID).Return(testNote, nil).Once()
				mockRepo.On("Delete", mock.Anything, noteID, userID).Return(nil).Once()
			},
			expectedErr: nil,
		},
		{
			name:   "error - invalid token",
			token:  "invalid-token",
			noteID: noteID,
			setupMocks: func(mockRepo *mockNoteRepository, mockTokenSvc *mockTokenService) {
				mockTokenSvc.On("ValidateAccessToken", mock.Anything, "invalid-token").
					Return("", ErrTokenInvalid).Once()
			},
			expectedErrMsg: "unauthorized access",
			expectedErr:    app.ErrUnauthorized,
		},
		{
			name:   "error - note not found",
			token:  token,
			noteID: "nonexistent-note",
			setupMocks: func(mockRepo *mockNoteRepository, mockTokenSvc *mockTokenService) {
				mockTokenSvc.On("ValidateAccessToken", mock.Anything, token).Return(userID, nil).Once()
				mockRepo.On("GetByID", mock.Anything, "nonexistent-note", userID).Return(nil, nil).Once()
			},
			expectedErrMsg: "note not found",
			expectedErr:    app.ErrNotFound,
		},
		{
			name:   "error - database error on get",
			token:  token,
			noteID: noteID,
			setupMocks: func(mockRepo *mockNoteRepository, mockTokenSvc *mockTokenService) {
				mockTokenSvc.On("ValidateAccessToken", mock.Anything, token).Return(userID, nil).Once()
				mockRepo.On("GetByID", mock.Anything, noteID, userID).Return(nil, ErrDatabaseOperation).Once()
			},
			expectedErrMsg: "failed to get note",
			expectedErr:    ErrDatabaseOperation,
		},
		{
			name:   "error - database error on delete",
			token:  token,
			noteID: noteID,
			setupMocks: func(mockRepo *mockNoteRepository, mockTokenSvc *mockTokenService) {
				mockTokenSvc.On("ValidateAccessToken", mock.Anything, token).Return(userID, nil).Once()
				mockRepo.On("GetByID", mock.Anything, noteID, userID).Return(testNote, nil).Once()
				mockRepo.On("Delete", mock.Anything, noteID, userID).Return(ErrDatabaseOperation).Once()
			},
			expectedErrMsg: "failed to delete note",
			expectedErr:    ErrDatabaseOperation,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockRepo := new(mockNoteRepository)
			mockTokenSvc := new(mockTokenService)

			tt.setupMocks(mockRepo, mockTokenSvc)

			useCase := app.NewNoteUseCase(mockRepo, mockTokenSvc)
			ctx := context.Background()

			err := useCase.DeleteNote(ctx, tt.token, tt.noteID)

			if tt.expectedErr != nil {
				require.Error(t, err)
				if errors.Is(tt.expectedErr, app.ErrUnauthorized) || errors.Is(tt.expectedErr, app.ErrNotFound) {
					assert.ErrorIs(t, err, tt.expectedErr)
				} else {
					assert.ErrorContains(t, err, tt.expectedErrMsg)
					if errors.Is(err, ErrDatabaseOperation) {
						assert.ErrorIs(t, errors.Unwrap(err), ErrDatabaseOperation)
					}
				}
			} else {
				require.NoError(t, err)
			}

			mockRepo.AssertExpectations(t)
			mockTokenSvc.AssertExpectations(t)
		})
	}
}
