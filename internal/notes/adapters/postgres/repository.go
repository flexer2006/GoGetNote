package postgres

import (
	"github.com/jackc/pgx/v5/pgxpool"

	"gogetnote/internal/notes/ports/repositories"
)

// RepositoryFactory создает репозитории для работы с базой данных.
type RepositoryFactory struct {
	pool *pgxpool.Pool
}

// NewRepositoryFactory создает новую фабрику репозиториев.
func NewRepositoryFactory(pool *pgxpool.Pool) *RepositoryFactory {
	return &RepositoryFactory{pool: pool}
}

// NoteRepository возвращает репозиторий для работы с заметками.
func (f *RepositoryFactory) NoteRepository() repositories.NoteRepository {
	return NewNoteRepository(f.pool)
}
