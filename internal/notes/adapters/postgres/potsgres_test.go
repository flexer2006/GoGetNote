package postgres_test

import (
	"context"
	"errors"
	"gogetnote/internal/notes/adapters/postgres"
	"gogetnote/internal/notes/domain/entities"
	"gogetnote/internal/notes/ports/repositories"
	"gogetnote/pkg/logger"
	"testing"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/pashagolub/pgxmock/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewNoteRepository(t *testing.T) {
	mockPool := &pgxpool.Pool{}

	repo := postgres.NewNoteRepository(mockPool)

	assert.NotNil(t, repo, "Repository should not be nil")
	assert.Implements(t, (*repositories.NoteRepository)(nil), repo, "Repository should implement NoteRepository interface")

	_, ok := repo.(*postgres.NoteRepository)
	assert.True(t, ok, "Repository should be of type *postgres.NoteRepository")
}

var (
	errDatabaseConnection  = errors.New("database connection failed")
	errForeignKeyViolation = errors.New("foreign key violation")
)

const (
	ErrCreatingNote = "failed to create note"
)

func TestNoteRepository_Create(t *testing.T) {
	ctx := context.Background()
	testLogger, err := logger.NewLogger(logger.Development, "debug")
	require.NoError(t, err)
	ctx = logger.NewContext(ctx, testLogger)

	inputNote := &entities.Note{
		UserID:  "user-123",
		Title:   "Test Note",
		Content: "This is a test note content.",
	}

	expectedNoteID := "note-abc-123"

	t.Run("successful note creation", func(t *testing.T) {
		mock, err := pgxmock.NewPool()
		require.NoError(t, err)
		defer mock.Close()

		mock.ExpectQuery("INSERT INTO notes \\(user_id, title, content\\) VALUES \\(\\$1, \\$2, \\$3\\) RETURNING id").
			WithArgs(inputNote.UserID, inputNote.Title, inputNote.Content).
			WillReturnRows(pgxmock.NewRows([]string{"id"}).AddRow(expectedNoteID))

		repo := postgres.NewNoteRepository(mock)
		noteID, err := repo.Create(ctx, inputNote)

		require.NoError(t, err)
		require.Equal(t, expectedNoteID, noteID)

		err = mock.ExpectationsWereMet()
		require.NoError(t, err)
	})

	t.Run("database connection error", func(t *testing.T) {
		mock, err := pgxmock.NewPool()
		require.NoError(t, err)
		defer mock.Close()

		mock.ExpectQuery("INSERT INTO notes \\(user_id, title, content\\) VALUES \\(\\$1, \\$2, \\$3\\) RETURNING id").
			WithArgs(inputNote.UserID, inputNote.Title, inputNote.Content).
			WillReturnError(errDatabaseConnection)

		repo := postgres.NewNoteRepository(mock)
		noteID, err := repo.Create(ctx, inputNote)

		require.Empty(t, noteID)
		require.Error(t, err)
		require.Contains(t, err.Error(), ErrCreatingNote)

		err = mock.ExpectationsWereMet()
		require.NoError(t, err)
	})

	t.Run("foreign key violation error", func(t *testing.T) {
		mock, err := pgxmock.NewPool()
		require.NoError(t, err)
		defer mock.Close()

		invalidNote := &entities.Note{
			UserID:  "non-existent-user",
			Title:   "Invalid Note",
			Content: "Note with invalid user ID",
		}

		mock.ExpectQuery("INSERT INTO notes \\(user_id, title, content\\) VALUES \\(\\$1, \\$2, \\$3\\) RETURNING id").
			WithArgs(invalidNote.UserID, invalidNote.Title, invalidNote.Content).
			WillReturnError(errForeignKeyViolation)

		repo := postgres.NewNoteRepository(mock)
		noteID, err := repo.Create(ctx, invalidNote)

		require.Empty(t, noteID)
		require.Error(t, err)
		require.Contains(t, err.Error(), ErrCreatingNote)

		err = mock.ExpectationsWereMet()
		require.NoError(t, err)
	})

	t.Run("note with empty title", func(t *testing.T) {
		mock, err := pgxmock.NewPool()
		require.NoError(t, err)
		defer mock.Close()

		minimalNote := &entities.Note{
			UserID:  "user-123",
			Title:   "",
			Content: "Note with empty title",
		}

		mock.ExpectQuery("INSERT INTO notes \\(user_id, title, content\\) VALUES \\(\\$1, \\$2, \\$3\\) RETURNING id").
			WithArgs(minimalNote.UserID, minimalNote.Title, minimalNote.Content).
			WillReturnRows(pgxmock.NewRows([]string{"id"}).AddRow(expectedNoteID))

		repo := postgres.NewNoteRepository(mock)
		noteID, err := repo.Create(ctx, minimalNote)

		require.NoError(t, err)
		require.Equal(t, expectedNoteID, noteID)

		err = mock.ExpectationsWereMet()
		require.NoError(t, err)
	})

	t.Run("note with empty content", func(t *testing.T) {
		mock, err := pgxmock.NewPool()
		require.NoError(t, err)
		defer mock.Close()

		minimalNote := &entities.Note{
			UserID:  "user-123",
			Title:   "Just a title",
			Content: "",
		}

		mock.ExpectQuery("INSERT INTO notes \\(user_id, title, content\\) VALUES \\(\\$1, \\$2, \\$3\\) RETURNING id").
			WithArgs(minimalNote.UserID, minimalNote.Title, minimalNote.Content).
			WillReturnRows(pgxmock.NewRows([]string{"id"}).AddRow(expectedNoteID))

		repo := postgres.NewNoteRepository(mock)
		noteID, err := repo.Create(ctx, minimalNote)

		require.NoError(t, err)
		require.Equal(t, expectedNoteID, noteID)

		err = mock.ExpectationsWereMet()
		require.NoError(t, err)
	})
}

var (
	errUpdateDatabase = errors.New("database update error")
)

const (
	ErrUpdatingNote = "failed to update note"
)

func TestNoteRepository_Update(t *testing.T) {
	ctx := context.Background()
	testLogger, err := logger.NewLogger(logger.Development, "debug")
	require.NoError(t, err)
	ctx = logger.NewContext(ctx, testLogger)

	noteToUpdate := &entities.Note{
		ID:      "note-123",
		UserID:  "user-123",
		Title:   "Updated Title",
		Content: "This is updated content for the test note.",
	}

	t.Run("successful note update", func(t *testing.T) {
		mock, err := pgxmock.NewPool()
		require.NoError(t, err)
		defer mock.Close()

		// Create a command tag that returns 1 for RowsAffected()
		commandTag := pgconn.NewCommandTag("UPDATE 1")

		mock.ExpectExec("UPDATE notes SET title = \\$1, content = \\$2 WHERE id = \\$3 AND user_id = \\$4").
			WithArgs(noteToUpdate.Title, noteToUpdate.Content, noteToUpdate.ID, noteToUpdate.UserID).
			WillReturnResult(commandTag)

		repo := postgres.NewNoteRepository(mock)
		err = repo.Update(ctx, noteToUpdate)

		require.NoError(t, err)
		err = mock.ExpectationsWereMet()
		require.NoError(t, err)
	})

	t.Run("database error during update", func(t *testing.T) {
		mock, err := pgxmock.NewPool()
		require.NoError(t, err)
		defer mock.Close()

		mock.ExpectExec("UPDATE notes SET title = \\$1, content = \\$2 WHERE id = \\$3 AND user_id = \\$4").
			WithArgs(noteToUpdate.Title, noteToUpdate.Content, noteToUpdate.ID, noteToUpdate.UserID).
			WillReturnError(errUpdateDatabase)

		repo := postgres.NewNoteRepository(mock)
		err = repo.Update(ctx, noteToUpdate)

		require.Error(t, err)
		require.Contains(t, err.Error(), ErrUpdatingNote)
		err = mock.ExpectationsWereMet()
		require.NoError(t, err)
	})

	t.Run("note not found or not owned by user", func(t *testing.T) {
		mock, err := pgxmock.NewPool()
		require.NoError(t, err)
		defer mock.Close()

		// Create a command tag that returns 0 for RowsAffected()
		commandTag := pgconn.NewCommandTag("UPDATE 0")

		mock.ExpectExec("UPDATE notes SET title = \\$1, content = \\$2 WHERE id = \\$3 AND user_id = \\$4").
			WithArgs(noteToUpdate.Title, noteToUpdate.Content, noteToUpdate.ID, noteToUpdate.UserID).
			WillReturnResult(commandTag)

		repo := postgres.NewNoteRepository(mock)
		err = repo.Update(ctx, noteToUpdate)

		require.Error(t, err)
		require.Equal(t, postgres.ErrNoteNotFoundOrNotOwned, err)
		err = mock.ExpectationsWereMet()
		require.NoError(t, err)
	})

	t.Run("update with empty title", func(t *testing.T) {
		mock, err := pgxmock.NewPool()
		require.NoError(t, err)
		defer mock.Close()

		emptyTitleNote := &entities.Note{
			ID:      "note-123",
			UserID:  "user-123",
			Title:   "",
			Content: "Content with empty title",
		}

		// Create a command tag that returns 1 for RowsAffected()
		commandTag := pgconn.NewCommandTag("UPDATE 1")

		mock.ExpectExec("UPDATE notes SET title = \\$1, content = \\$2 WHERE id = \\$3 AND user_id = \\$4").
			WithArgs(emptyTitleNote.Title, emptyTitleNote.Content, emptyTitleNote.ID, emptyTitleNote.UserID).
			WillReturnResult(commandTag)

		repo := postgres.NewNoteRepository(mock)
		err = repo.Update(ctx, emptyTitleNote)

		require.NoError(t, err)
		err = mock.ExpectationsWereMet()
		require.NoError(t, err)
	})

	t.Run("update with empty content", func(t *testing.T) {
		mock, err := pgxmock.NewPool()
		require.NoError(t, err)
		defer mock.Close()

		emptyContentNote := &entities.Note{
			ID:      "note-123",
			UserID:  "user-123",
			Title:   "Title with empty content",
			Content: "",
		}

		// Create a command tag that returns 1 for RowsAffected()
		commandTag := pgconn.NewCommandTag("UPDATE 1")

		mock.ExpectExec("UPDATE notes SET title = \\$1, content = \\$2 WHERE id = \\$3 AND user_id = \\$4").
			WithArgs(emptyContentNote.Title, emptyContentNote.Content, emptyContentNote.ID, emptyContentNote.UserID).
			WillReturnResult(commandTag)

		repo := postgres.NewNoteRepository(mock)
		err = repo.Update(ctx, emptyContentNote)

		require.NoError(t, err)
		err = mock.ExpectationsWereMet()
		require.NoError(t, err)
	})

	t.Run("update with invalid note ID", func(t *testing.T) {
		mock, err := pgxmock.NewPool()
		require.NoError(t, err)
		defer mock.Close()

		invalidIDNote := &entities.Note{
			ID:      "invalid-note-id",
			UserID:  "user-123",
			Title:   "Invalid Note",
			Content: "This note has an invalid ID",
		}

		// Create a command tag that returns 0 for RowsAffected()
		commandTag := pgconn.NewCommandTag("UPDATE 0")

		mock.ExpectExec("UPDATE notes SET title = \\$1, content = \\$2 WHERE id = \\$3 AND user_id = \\$4").
			WithArgs(invalidIDNote.Title, invalidIDNote.Content, invalidIDNote.ID, invalidIDNote.UserID).
			WillReturnResult(commandTag)

		repo := postgres.NewNoteRepository(mock)
		err = repo.Update(ctx, invalidIDNote)

		require.Error(t, err)
		require.Equal(t, postgres.ErrNoteNotFoundOrNotOwned, err)
		err = mock.ExpectationsWereMet()
		require.NoError(t, err)
	})

	t.Run("update with unauthorized user", func(t *testing.T) {
		mock, err := pgxmock.NewPool()
		require.NoError(t, err)
		defer mock.Close()

		unauthorizedNote := &entities.Note{
			ID:      "note-123",
			UserID:  "unauthorized-user",
			Title:   "Unauthorized Update",
			Content: "This update is from an unauthorized user",
		}

		// Create a command tag that returns 0 for RowsAffected()
		commandTag := pgconn.NewCommandTag("UPDATE 0")

		mock.ExpectExec("UPDATE notes SET title = \\$1, content = \\$2 WHERE id = \\$3 AND user_id = \\$4").
			WithArgs(unauthorizedNote.Title, unauthorizedNote.Content, unauthorizedNote.ID, unauthorizedNote.UserID).
			WillReturnResult(commandTag)

		repo := postgres.NewNoteRepository(mock)
		err = repo.Update(ctx, unauthorizedNote)

		require.Error(t, err)
		require.Equal(t, postgres.ErrNoteNotFoundOrNotOwned, err)
		err = mock.ExpectationsWereMet()
		require.NoError(t, err)
	})
}

var (
	errDeleteDatabase = errors.New("database delete error")
)

const (
	ErrDeletingNote = "failed to delete note"
)

func TestNoteRepository_Delete(t *testing.T) {
	ctx := context.Background()
	testLogger, err := logger.NewLogger(logger.Development, "debug")
	require.NoError(t, err)
	ctx = logger.NewContext(ctx, testLogger)

	noteID := "note-123"
	userID := "user-123"

	t.Run("successful note deletion", func(t *testing.T) {
		mock, err := pgxmock.NewPool()
		require.NoError(t, err)
		defer mock.Close()

		// Create a command tag that returns 1 for RowsAffected()
		commandTag := pgconn.NewCommandTag("DELETE 1")

		mock.ExpectExec("DELETE FROM notes WHERE id = \\$1 AND user_id = \\$2").
			WithArgs(noteID, userID).
			WillReturnResult(commandTag)

		repo := postgres.NewNoteRepository(mock)
		err = repo.Delete(ctx, noteID, userID)

		require.NoError(t, err)
		err = mock.ExpectationsWereMet()
		require.NoError(t, err)
	})

	t.Run("database error during deletion", func(t *testing.T) {
		mock, err := pgxmock.NewPool()
		require.NoError(t, err)
		defer mock.Close()

		mock.ExpectExec("DELETE FROM notes WHERE id = \\$1 AND user_id = \\$2").
			WithArgs(noteID, userID).
			WillReturnError(errDeleteDatabase)

		repo := postgres.NewNoteRepository(mock)
		err = repo.Delete(ctx, noteID, userID)

		require.Error(t, err)
		require.Contains(t, err.Error(), ErrDeletingNote)
		err = mock.ExpectationsWereMet()
		require.NoError(t, err)
	})

	t.Run("note not found or not owned by user", func(t *testing.T) {
		mock, err := pgxmock.NewPool()
		require.NoError(t, err)
		defer mock.Close()

		// Create a command tag that returns 0 for RowsAffected()
		commandTag := pgconn.NewCommandTag("DELETE 0")

		mock.ExpectExec("DELETE FROM notes WHERE id = \\$1 AND user_id = \\$2").
			WithArgs(noteID, userID).
			WillReturnResult(commandTag)

		repo := postgres.NewNoteRepository(mock)
		err = repo.Delete(ctx, noteID, userID)

		require.Error(t, err)
		require.Equal(t, postgres.ErrNoteNotFoundOrNotOwned, err)
		err = mock.ExpectationsWereMet()
		require.NoError(t, err)
	})

	t.Run("delete with invalid note ID", func(t *testing.T) {
		mock, err := pgxmock.NewPool()
		require.NoError(t, err)
		defer mock.Close()

		invalidNoteID := "invalid-note-id"

		// Create a command tag that returns 0 for RowsAffected()
		commandTag := pgconn.NewCommandTag("DELETE 0")

		mock.ExpectExec("DELETE FROM notes WHERE id = \\$1 AND user_id = \\$2").
			WithArgs(invalidNoteID, userID).
			WillReturnResult(commandTag)

		repo := postgres.NewNoteRepository(mock)
		err = repo.Delete(ctx, invalidNoteID, userID)

		require.Error(t, err)
		require.Equal(t, postgres.ErrNoteNotFoundOrNotOwned, err)
		err = mock.ExpectationsWereMet()
		require.NoError(t, err)
	})

	t.Run("delete with unauthorized user", func(t *testing.T) {
		mock, err := pgxmock.NewPool()
		require.NoError(t, err)
		defer mock.Close()

		unauthorizedUserID := "unauthorized-user"

		// Create a command tag that returns 0 for RowsAffected()
		commandTag := pgconn.NewCommandTag("DELETE 0")

		mock.ExpectExec("DELETE FROM notes WHERE id = \\$1 AND user_id = \\$2").
			WithArgs(noteID, unauthorizedUserID).
			WillReturnResult(commandTag)

		repo := postgres.NewNoteRepository(mock)
		err = repo.Delete(ctx, noteID, unauthorizedUserID)

		require.Error(t, err)
		require.Equal(t, postgres.ErrNoteNotFoundOrNotOwned, err)
		err = mock.ExpectationsWereMet()
		require.NoError(t, err)
	})

	t.Run("delete with empty note ID", func(t *testing.T) {
		mock, err := pgxmock.NewPool()
		require.NoError(t, err)
		defer mock.Close()

		emptyNoteID := ""

		// Create a command tag that returns 0 for RowsAffected()
		commandTag := pgconn.NewCommandTag("DELETE 0")

		mock.ExpectExec("DELETE FROM notes WHERE id = \\$1 AND user_id = \\$2").
			WithArgs(emptyNoteID, userID).
			WillReturnResult(commandTag)

		repo := postgres.NewNoteRepository(mock)
		err = repo.Delete(ctx, emptyNoteID, userID)

		require.Error(t, err)
		require.Equal(t, postgres.ErrNoteNotFoundOrNotOwned, err)
		err = mock.ExpectationsWereMet()
		require.NoError(t, err)
	})
}
