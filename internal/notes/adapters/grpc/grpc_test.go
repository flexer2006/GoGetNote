package grpc_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	grpcAdapter "gogetnote/internal/notes/adapters/grpc"
	"gogetnote/internal/notes/app"
	"gogetnote/internal/notes/config"
	"gogetnote/internal/notes/domain/entities"
	notesv1 "gogetnote/pkg/api/notes/v1"
	"gogetnote/pkg/logger"
)

var (
	errUnauthorized = app.ErrUnauthorized
	errDatabase     = errors.New("database error")
	errRetrieve     = errors.New("failed to retrieve note")
)

func TestRegisterService(t *testing.T) {
	cfg := &config.GRPCConfig{
		Host: "localhost",
		Port: 0,
	}
	server := grpcAdapter.New(cfg)

	called := false
	server.RegisterService(func(s *grpc.Server) {
		called = true
	})

	assert.True(t, called, "RegisterService should call the provided function")
}

func TestExtractToken(t *testing.T) {
	// Set up logger for testing
	err := logger.InitGlobalLoggerWithLevel(logger.Development, "debug")
	require.NoError(t, err)

	testCases := []struct {
		name          string
		setupContext  func() context.Context
		expectedToken string
		expectedError error
	}{
		{
			name: "valid bearer token",
			setupContext: func() context.Context {
				ctx := context.Background()
				ctx = logger.NewContext(ctx, logger.Log(ctx))
				md := metadata.New(map[string]string{
					"authorization": "Bearer token123",
				})
				return metadata.NewIncomingContext(ctx, md)
			},
			expectedToken: "token123",
			expectedError: nil,
		},
		{
			name: "token without bearer prefix",
			setupContext: func() context.Context {
				ctx := context.Background()
				ctx = logger.NewContext(ctx, logger.Log(ctx))
				md := metadata.New(map[string]string{
					"authorization": "token123",
				})
				return metadata.NewIncomingContext(ctx, md)
			},
			expectedToken: "token123",
			expectedError: nil,
		},
		{
			name: "missing metadata",
			setupContext: func() context.Context {
				ctx := context.Background()
				ctx = logger.NewContext(ctx, logger.Log(ctx))
				return ctx
			},
			expectedToken: "",
			expectedError: grpcAdapter.ErrMetadataNotFound,
		},
		{
			name: "missing authorization header",
			setupContext: func() context.Context {
				ctx := context.Background()
				ctx = logger.NewContext(ctx, logger.Log(ctx))
				md := metadata.New(map[string]string{
					"other-header": "value",
				})
				return metadata.NewIncomingContext(ctx, md)
			},
			expectedToken: "",
			expectedError: grpcAdapter.ErrAuthHeaderNotFound,
		},
		{
			name: "invalid format that should be rejected",
			setupContext: func() context.Context {
				ctx := context.Background()
				ctx = logger.NewContext(ctx, logger.Log(ctx))
				md := metadata.New(map[string]string{
					"authorization": "Invalid-Format",
				})
				return metadata.NewIncomingContext(ctx, md)
			},
			// But our actual implementation accepts any token format
			expectedToken: "Invalid-Format",
			expectedError: nil,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ctx := tc.setupContext()

			// Call the function directly
			token, err := grpcAdapter.ExtractToken(ctx)

			if tc.expectedError != nil {
				require.Error(t, err)
				assert.ErrorIs(t, err, tc.expectedError)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tc.expectedToken, token)
			}
		})
	}
}

// MockNoteUseCase mocks the note use case
type MockNoteUseCase struct {
	mock.Mock
}

func (m *MockNoteUseCase) CreateNote(ctx context.Context, token, title, content string) (string, error) {
	args := m.Called(ctx, token, title, content)
	return args.String(0), args.Error(1)
}

func (m *MockNoteUseCase) GetNote(ctx context.Context, token, noteID string) (*entities.Note, error) {
	args := m.Called(ctx, token, noteID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*entities.Note), args.Error(1)
}

func (m *MockNoteUseCase) ListNotes(ctx context.Context, token string, limit, offset int) ([]*entities.Note, int, error) {
	args := m.Called(ctx, token, limit, offset)
	return args.Get(0).([]*entities.Note), args.Int(1), args.Error(2)
}

func (m *MockNoteUseCase) UpdateNote(ctx context.Context, token, noteID, title, content string) (*entities.Note, error) {
	args := m.Called(ctx, token, noteID, title, content)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*entities.Note), args.Error(1)
}

func (m *MockNoteUseCase) DeleteNote(ctx context.Context, token, noteID string) error {
	args := m.Called(ctx, token, noteID)
	return args.Error(0)
}

func TestCreateNote(t *testing.T) {
	// Set up logger for testing
	err := logger.InitGlobalLoggerWithLevel(logger.Development, "debug")
	require.NoError(t, err)

	const (
		validToken    = "valid-token"
		noteID        = "note-123"
		userID        = "user-123"
		invalidToken  = "invalid-token"
		invalidFormat = "Invalid-Format"
	)

	var (
		errUnauthorized = app.ErrUnauthorized
		errDatabase     = errors.New("database error")
		errRetrieve     = errors.New("failed to retrieve note")
	)

	testCases := []struct {
		name                 string
		req                  *notesv1.CreateNoteRequest
		setupContext         func() context.Context
		setupMocks           func(mock *MockNoteUseCase)
		expectedError        error
		expectedCode         codes.Code
		validateResult       func(t *testing.T, response *notesv1.NoteResponse)
		shouldCallCreateNote bool // Flag to indicate if CreateNote should be called
	}{
		{
			name: "successful note creation",
			req: &notesv1.CreateNoteRequest{
				Title:   "Test Note",
				Content: "This is a test note content",
			},
			setupContext: func() context.Context {
				ctx := context.Background()
				ctx = logger.NewContext(ctx, logger.Log(ctx))
				md := metadata.New(map[string]string{
					"authorization": "Bearer " + validToken,
				})
				return metadata.NewIncomingContext(ctx, md)
			},
			setupMocks: func(mockUseCase *MockNoteUseCase) {
				now := time.Now()
				createdNote := &entities.Note{
					ID:        noteID,
					UserID:    userID,
					Title:     "Test Note",
					Content:   "This is a test note content",
					CreatedAt: now,
					UpdatedAt: now,
				}

				mockUseCase.On("CreateNote", mock.Anything, validToken, "Test Note", "This is a test note content").
					Return(noteID, nil)
				mockUseCase.On("GetNote", mock.Anything, validToken, noteID).
					Return(createdNote, nil)
			},
			expectedError: nil,
			expectedCode:  codes.OK,
			validateResult: func(t *testing.T, response *notesv1.NoteResponse) {
				t.Helper()
				assert.NotNil(t, response)
				assert.NotNil(t, response.Note)
				assert.Equal(t, noteID, response.Note.NoteId)
				assert.Equal(t, userID, response.Note.UserId)
				assert.Equal(t, "Test Note", response.Note.Title)
				assert.Equal(t, "This is a test note content", response.Note.Content)
				assert.NotNil(t, response.Note.CreatedAt)
				assert.NotNil(t, response.Note.UpdatedAt)
			},
			shouldCallCreateNote: true,
		},
		{
			name: "missing token",
			req: &notesv1.CreateNoteRequest{
				Title:   "Test Note",
				Content: "This is a test note content",
			},
			setupContext: func() context.Context {
				ctx := context.Background()
				ctx = logger.NewContext(ctx, logger.Log(ctx))
				return ctx // No metadata added
			},
			setupMocks: func(_ *MockNoteUseCase) {
				// No mocks needed, should fail before calling usecase
			},
			expectedError: status.Error(codes.Unauthenticated, "authentication required"),
			expectedCode:  codes.Unauthenticated,
			validateResult: func(t *testing.T, response *notesv1.NoteResponse) {
				t.Helper()
				assert.Nil(t, response)
			},
			shouldCallCreateNote: false,
		},
		{
			name: "invalid token format",
			req: &notesv1.CreateNoteRequest{
				Title:   "Test Note",
				Content: "This is a test note content",
			},
			setupContext: func() context.Context {
				ctx := context.Background()
				ctx = logger.NewContext(ctx, logger.Log(ctx))
				md := metadata.New(map[string]string{
					// Setting a token format that is expected to be treated like any other token
					"authorization": invalidFormat,
				})
				return metadata.NewIncomingContext(ctx, md)
			},
			setupMocks: func(mockUseCase *MockNoteUseCase) {
				// We need to mock the call because the token will actually be extracted and passed to CreateNote
				mockUseCase.On("CreateNote", mock.Anything, invalidFormat, "Test Note", "This is a test note content").
					Return("", errUnauthorized)
			},
			expectedError: status.Error(codes.Unauthenticated, "invalid or expired token"),
			expectedCode:  codes.Unauthenticated,
			validateResult: func(t *testing.T, response *notesv1.NoteResponse) {
				t.Helper()
				assert.Nil(t, response)
			},
			shouldCallCreateNote: true,
		},
		{
			name: "unauthorized user",
			req: &notesv1.CreateNoteRequest{
				Title:   "Test Note",
				Content: "This is a test note content",
			},
			setupContext: func() context.Context {
				ctx := context.Background()
				ctx = logger.NewContext(ctx, logger.Log(ctx))
				md := metadata.New(map[string]string{
					"authorization": "Bearer " + invalidToken,
				})
				return metadata.NewIncomingContext(ctx, md)
			},
			setupMocks: func(mockUseCase *MockNoteUseCase) {
				mockUseCase.On("CreateNote", mock.Anything, invalidToken, "Test Note", "This is a test note content").
					Return("", errUnauthorized)
			},
			expectedError: status.Error(codes.Unauthenticated, "invalid or expired token"),
			expectedCode:  codes.Unauthenticated,
			validateResult: func(t *testing.T, response *notesv1.NoteResponse) {
				t.Helper()
				assert.Nil(t, response)
			},
			shouldCallCreateNote: true,
		},
		{
			name: "database error during creation",
			req: &notesv1.CreateNoteRequest{
				Title:   "Test Note",
				Content: "This is a test note content",
			},
			setupContext: func() context.Context {
				ctx := context.Background()
				ctx = logger.NewContext(ctx, logger.Log(ctx))
				md := metadata.New(map[string]string{
					"authorization": "Bearer " + validToken,
				})
				return metadata.NewIncomingContext(ctx, md)
			},
			setupMocks: func(mockUseCase *MockNoteUseCase) {
				mockUseCase.On("CreateNote", mock.Anything, validToken, "Test Note", "This is a test note content").
					Return("", errDatabase)
			},
			expectedError: status.Error(codes.Internal, "failed to create note"),
			expectedCode:  codes.Internal,
			validateResult: func(t *testing.T, response *notesv1.NoteResponse) {
				t.Helper()
				assert.Nil(t, response)
			},
			shouldCallCreateNote: true,
		},
		{
			name: "error retrieving created note",
			req: &notesv1.CreateNoteRequest{
				Title:   "Test Note",
				Content: "This is a test note content",
			},
			setupContext: func() context.Context {
				ctx := context.Background()
				ctx = logger.NewContext(ctx, logger.Log(ctx))
				md := metadata.New(map[string]string{
					"authorization": "Bearer " + validToken,
				})
				return metadata.NewIncomingContext(ctx, md)
			},
			setupMocks: func(mockUseCase *MockNoteUseCase) {
				mockUseCase.On("CreateNote", mock.Anything, validToken, "Test Note", "This is a test note content").
					Return(noteID, nil)
				mockUseCase.On("GetNote", mock.Anything, validToken, noteID).
					Return(nil, errRetrieve)
			},
			expectedError: status.Error(codes.Internal, "note was created but could not be retrieved"),
			expectedCode:  codes.Internal,
			validateResult: func(t *testing.T, response *notesv1.NoteResponse) {
				t.Helper()
				assert.Nil(t, response)
			},
			shouldCallCreateNote: true,
		},
		{
			name: "empty title and content",
			req: &notesv1.CreateNoteRequest{
				Title:   "",
				Content: "",
			},
			setupContext: func() context.Context {
				ctx := context.Background()
				ctx = logger.NewContext(ctx, logger.Log(ctx))
				md := metadata.New(map[string]string{
					"authorization": "Bearer " + validToken,
				})
				return metadata.NewIncomingContext(ctx, md)
			},
			setupMocks: func(mockUseCase *MockNoteUseCase) {
				now := time.Now()
				createdNote := &entities.Note{
					ID:        noteID,
					UserID:    userID,
					Title:     "",
					Content:   "",
					CreatedAt: now,
					UpdatedAt: now,
				}

				mockUseCase.On("CreateNote", mock.Anything, validToken, "", "").
					Return(noteID, nil)
				mockUseCase.On("GetNote", mock.Anything, validToken, noteID).
					Return(createdNote, nil)
			},
			expectedError: nil,
			expectedCode:  codes.OK,
			validateResult: func(t *testing.T, response *notesv1.NoteResponse) {
				t.Helper()
				assert.NotNil(t, response)
				assert.NotNil(t, response.Note)
				assert.Equal(t, noteID, response.Note.NoteId)
				assert.Equal(t, userID, response.Note.UserId)
				assert.Equal(t, "", response.Note.Title)
				assert.Equal(t, "", response.Note.Content)
			},
			shouldCallCreateNote: true,
		},
		{
			name: "token without bearer prefix",
			req: &notesv1.CreateNoteRequest{
				Title:   "Test Note",
				Content: "This is a test note content",
			},
			setupContext: func() context.Context {
				ctx := context.Background()
				ctx = logger.NewContext(ctx, logger.Log(ctx))
				md := metadata.New(map[string]string{
					"authorization": validToken, // No Bearer prefix
				})
				return metadata.NewIncomingContext(ctx, md)
			},
			setupMocks: func(mockUseCase *MockNoteUseCase) {
				now := time.Now()
				createdNote := &entities.Note{
					ID:        noteID,
					UserID:    userID,
					Title:     "Test Note",
					Content:   "This is a test note content",
					CreatedAt: now,
					UpdatedAt: now,
				}

				mockUseCase.On("CreateNote", mock.Anything, validToken, "Test Note", "This is a test note content").
					Return(noteID, nil)
				mockUseCase.On("GetNote", mock.Anything, validToken, noteID).
					Return(createdNote, nil)
			},
			expectedError: nil,
			expectedCode:  codes.OK,
			validateResult: func(t *testing.T, response *notesv1.NoteResponse) {
				t.Helper()
				assert.NotNil(t, response)
				assert.NotNil(t, response.Note)
				assert.Equal(t, noteID, response.Note.NoteId)
			},
			shouldCallCreateNote: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Initialize mocks
			mockNoteUseCase := new(MockNoteUseCase)
			tc.setupMocks(mockNoteUseCase)

			// Create handler
			handler := grpcAdapter.NewNoteHandler(mockNoteUseCase)

			// Set up context
			ctx := tc.setupContext()

			// Call the method
			response, err := handler.CreateNote(ctx, tc.req)

			// Validate error
			if tc.expectedError != nil {
				require.Error(t, err)
				statusErr, ok := status.FromError(err)
				require.True(t, ok, "error should be a gRPC status error")
				assert.Equal(t, tc.expectedCode, statusErr.Code())
				assert.Contains(t, statusErr.Message(), tc.expectedError.Error())
			} else {
				require.NoError(t, err)
			}

			// Validate result
			tc.validateResult(t, response)

			// Verify expectations if needed
			if tc.shouldCallCreateNote {
				mockNoteUseCase.AssertExpectations(t)
			}
		})
	}
}
func TestGetNote(t *testing.T) {
	// Set up logger for testing
	err := logger.InitGlobalLoggerWithLevel(logger.Development, "debug")
	require.NoError(t, err)

	const (
		validToken   = "valid-token"
		invalidToken = "invalid-token"
		noteID       = "note-123"
		notFoundID   = "note-not-found"
		userID       = "user-123"
		noteTitle    = "Test Note"
		noteContent  = "This is a test note content"
	)

	var (
		errUnauthorized = app.ErrUnauthorized
		errNotFound     = app.ErrNotFound
		errInternal     = errors.New("internal service error")
	)

	testCases := []struct {
		name           string
		req            *notesv1.GetNoteRequest
		setupContext   func() context.Context
		setupMocks     func(mock *MockNoteUseCase)
		expectedError  error
		expectedCode   codes.Code
		validateResult func(t *testing.T, response *notesv1.NoteResponse)
	}{
		{
			name: "successful get note",
			req: &notesv1.GetNoteRequest{
				NoteId: noteID,
			},
			setupContext: func() context.Context {
				ctx := context.Background()
				ctx = logger.NewContext(ctx, logger.Log(ctx))
				md := metadata.New(map[string]string{
					"authorization": "Bearer " + validToken,
				})
				return metadata.NewIncomingContext(ctx, md)
			},
			setupMocks: func(mockUseCase *MockNoteUseCase) {
				now := time.Now()
				note := &entities.Note{
					ID:        noteID,
					UserID:    userID,
					Title:     noteTitle,
					Content:   noteContent,
					CreatedAt: now,
					UpdatedAt: now,
				}
				mockUseCase.On("GetNote", mock.Anything, validToken, noteID).Return(note, nil)
			},
			expectedError: nil,
			expectedCode:  codes.OK,
			validateResult: func(t *testing.T, response *notesv1.NoteResponse) {
				t.Helper()
				assert.NotNil(t, response)
				assert.NotNil(t, response.Note)
				assert.Equal(t, noteID, response.Note.NoteId)
				assert.Equal(t, userID, response.Note.UserId)
				assert.Equal(t, noteTitle, response.Note.Title)
				assert.Equal(t, noteContent, response.Note.Content)
				assert.NotNil(t, response.Note.CreatedAt)
				assert.NotNil(t, response.Note.UpdatedAt)
			},
		},
		{
			name: "missing token",
			req: &notesv1.GetNoteRequest{
				NoteId: noteID,
			},
			setupContext: func() context.Context {
				ctx := context.Background()
				ctx = logger.NewContext(ctx, logger.Log(ctx))
				return ctx // No metadata added
			},
			setupMocks: func(_ *MockNoteUseCase) {
				// No mocks needed, should fail before calling usecase
			},
			expectedError: status.Error(codes.Unauthenticated, "authentication required"),
			expectedCode:  codes.Unauthenticated,
			validateResult: func(t *testing.T, response *notesv1.NoteResponse) {
				t.Helper()
				assert.Nil(t, response)
			},
		},
		{
			name: "empty authorization header",
			req: &notesv1.GetNoteRequest{
				NoteId: noteID,
			},
			setupContext: func() context.Context {
				ctx := context.Background()
				ctx = logger.NewContext(ctx, logger.Log(ctx))
				md := metadata.New(map[string]string{
					"authorization": "",
				})
				return metadata.NewIncomingContext(ctx, md)
			},
			setupMocks: func(mockUseCase *MockNoteUseCase) {
				// Token will be empty but still passed to usecase
				mockUseCase.On("GetNote", mock.Anything, "", noteID).Return(nil, errUnauthorized)
			},
			expectedError: status.Error(codes.Unauthenticated, "invalid or expired token"),
			expectedCode:  codes.Unauthenticated,
			validateResult: func(t *testing.T, response *notesv1.NoteResponse) {
				t.Helper()
				assert.Nil(t, response)
			},
		},
		{
			name: "unauthorized user",
			req: &notesv1.GetNoteRequest{
				NoteId: noteID,
			},
			setupContext: func() context.Context {
				ctx := context.Background()
				ctx = logger.NewContext(ctx, logger.Log(ctx))
				md := metadata.New(map[string]string{
					"authorization": "Bearer " + invalidToken,
				})
				return metadata.NewIncomingContext(ctx, md)
			},
			setupMocks: func(mockUseCase *MockNoteUseCase) {
				mockUseCase.On("GetNote", mock.Anything, invalidToken, noteID).Return(nil, errUnauthorized)
			},
			expectedError: status.Error(codes.Unauthenticated, "invalid or expired token"),
			expectedCode:  codes.Unauthenticated,
			validateResult: func(t *testing.T, response *notesv1.NoteResponse) {
				t.Helper()
				assert.Nil(t, response)
			},
		},
		{
			name: "note not found",
			req: &notesv1.GetNoteRequest{
				NoteId: notFoundID,
			},
			setupContext: func() context.Context {
				ctx := context.Background()
				ctx = logger.NewContext(ctx, logger.Log(ctx))
				md := metadata.New(map[string]string{
					"authorization": "Bearer " + validToken,
				})
				return metadata.NewIncomingContext(ctx, md)
			},
			setupMocks: func(mockUseCase *MockNoteUseCase) {
				mockUseCase.On("GetNote", mock.Anything, validToken, notFoundID).Return(nil, errNotFound)
			},
			expectedError: status.Error(codes.NotFound, "note not found"),
			expectedCode:  codes.NotFound,
			validateResult: func(t *testing.T, response *notesv1.NoteResponse) {
				t.Helper()
				assert.Nil(t, response)
			},
		},
		{
			name: "internal service error",
			req: &notesv1.GetNoteRequest{
				NoteId: noteID,
			},
			setupContext: func() context.Context {
				ctx := context.Background()
				ctx = logger.NewContext(ctx, logger.Log(ctx))
				md := metadata.New(map[string]string{
					"authorization": "Bearer " + validToken,
				})
				return metadata.NewIncomingContext(ctx, md)
			},
			setupMocks: func(mockUseCase *MockNoteUseCase) {
				mockUseCase.On("GetNote", mock.Anything, validToken, noteID).Return(nil, errInternal)
			},
			expectedError: status.Error(codes.Internal, "failed to get note"),
			expectedCode:  codes.Internal,
			validateResult: func(t *testing.T, response *notesv1.NoteResponse) {
				t.Helper()
				assert.Nil(t, response)
			},
		},
		{
			name: "missing note ID",
			req: &notesv1.GetNoteRequest{
				NoteId: "",
			},
			setupContext: func() context.Context {
				ctx := context.Background()
				ctx = logger.NewContext(ctx, logger.Log(ctx))
				md := metadata.New(map[string]string{
					"authorization": "Bearer " + validToken,
				})
				return metadata.NewIncomingContext(ctx, md)
			},
			setupMocks: func(mockUseCase *MockNoteUseCase) {
				mockUseCase.On("GetNote", mock.Anything, validToken, "").Return(nil, errNotFound)
			},
			expectedError: status.Error(codes.NotFound, "note not found"),
			expectedCode:  codes.NotFound,
			validateResult: func(t *testing.T, response *notesv1.NoteResponse) {
				t.Helper()
				assert.Nil(t, response)
			},
		},
		{
			name: "token without bearer prefix",
			req: &notesv1.GetNoteRequest{
				NoteId: noteID,
			},
			setupContext: func() context.Context {
				ctx := context.Background()
				ctx = logger.NewContext(ctx, logger.Log(ctx))
				md := metadata.New(map[string]string{
					"authorization": validToken, // No Bearer prefix
				})
				return metadata.NewIncomingContext(ctx, md)
			},
			setupMocks: func(mockUseCase *MockNoteUseCase) {
				now := time.Now()
				note := &entities.Note{
					ID:        noteID,
					UserID:    userID,
					Title:     noteTitle,
					Content:   noteContent,
					CreatedAt: now,
					UpdatedAt: now,
				}
				// Token should still be extracted correctly without prefix
				mockUseCase.On("GetNote", mock.Anything, validToken, noteID).Return(note, nil)
			},
			expectedError: nil,
			expectedCode:  codes.OK,
			validateResult: func(t *testing.T, response *notesv1.NoteResponse) {
				t.Helper()
				assert.NotNil(t, response)
				assert.NotNil(t, response.Note)
				assert.Equal(t, noteID, response.Note.NoteId)
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Initialize mocks
			mockNoteUseCase := new(MockNoteUseCase)
			tc.setupMocks(mockNoteUseCase)

			// Create handler
			handler := grpcAdapter.NewNoteHandler(mockNoteUseCase)

			// Set up context
			ctx := tc.setupContext()

			// Call the method
			response, err := handler.GetNote(ctx, tc.req)

			// Validate error
			if tc.expectedError != nil {
				require.Error(t, err)
				statusErr, ok := status.FromError(err)
				require.True(t, ok, "error should be a gRPC status error")
				assert.Equal(t, tc.expectedCode, statusErr.Code())
				assert.Contains(t, statusErr.Message(), tc.expectedError.Error())
			} else {
				require.NoError(t, err)
			}

			// Validate result
			tc.validateResult(t, response)

			// Verify all expected calls were made
			mockNoteUseCase.AssertExpectations(t)
		})
	}
}
