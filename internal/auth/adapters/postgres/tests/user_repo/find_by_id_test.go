package userrepo_test

import (
	"context"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/pashagolub/pgxmock/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"gogetnote/internal/auth/adapters/postgres"
	"gogetnote/internal/auth/domain/entities"
	"gogetnote/pkg/logger"
)

const ErrQueryingUserByID = "error querying user by id"

func setupUserMock(mock pgxmock.PgxPoolIface, param any, testUser entities.User) {
	rows := pgxmock.NewRows([]string{"id", "email", "username", "password_hash", "created_at", "updated_at"}).
		AddRow(testUser.ID, testUser.Email, testUser.Username, testUser.PasswordHash, testUser.CreatedAt, testUser.UpdatedAt)

	mock.ExpectQuery("SELECT id, email, username, password_hash, created_at, updated_at").
		WithArgs(param).
		WillReturnRows(rows)
}

func TestUserRepository_FindByID(t *testing.T) {
	ctx := context.Background()
	testLogger, err := logger.NewLogger(logger.Development, "debug")
	require.NoError(t, err)
	ctx = logger.NewContext(ctx, testLogger)

	testUser := entities.User{
		ID:           "test-user-id",
		Email:        "test@example.com",
		Username:     "testuser",
		PasswordHash: "hashed_password",
		CreatedAt:    time.Now().UTC().Truncate(time.Microsecond),
		UpdatedAt:    time.Now().UTC().Truncate(time.Microsecond),
	}

	t.Run("successful user acquisition", func(t *testing.T) {
		mock, err := pgxmock.NewPool()
		require.NoError(t, err)
		defer mock.Close()

		setupUserMock(mock, testUser.ID, testUser)

		repo := postgres.NewUserRepository(mock)

		user, err := repo.FindByID(ctx, testUser.ID)

		require.NoError(t, err)

		assertUserEquals(t, &testUser, user)

		err = mock.ExpectationsWereMet()
		require.NoError(t, err)
	})

	t.Run("the user was not found", func(t *testing.T) {
		mock, err := pgxmock.NewPool()
		require.NoError(t, err)
		defer mock.Close()

		mock.ExpectQuery("SELECT id, email, username, password_hash, created_at, updated_at").
			WithArgs("non-existing-id").
			WillReturnError(pgx.ErrNoRows)

		repo := postgres.NewUserRepository(mock)

		user, err := repo.FindByID(ctx, "non-existing-id")

		require.Nil(t, user)
		require.ErrorIs(t, err, entities.ErrUserNotFound)

		err = mock.ExpectationsWereMet()
		require.NoError(t, err)
	})

	t.Run("database error", func(t *testing.T) {
		mock, err := pgxmock.NewPool()
		require.NoError(t, err)
		defer mock.Close()

		mock.ExpectQuery("SELECT id, email, username, password_hash, created_at, updated_at").
			WithArgs(testUser.ID).
			WillReturnError(errDatabaseConnection)

		repo := postgres.NewUserRepository(mock)

		user, err := repo.FindByID(ctx, testUser.ID)

		assert.Nil(t, user)
		require.Error(t, err)
		assert.Contains(t, err.Error(), ErrQueryingUserByID)

		err = mock.ExpectationsWereMet()
		require.NoError(t, err)
	})

	t.Run("empty email", func(t *testing.T) {
		mock, err := pgxmock.NewPool()
		require.NoError(t, err)
		defer mock.Close()

		mock.ExpectQuery("SELECT id, email, username, password_hash, created_at, updated_at").
			WithArgs("").
			WillReturnError(pgx.ErrNoRows)

		repo := postgres.NewUserRepository(mock)

		user, err := repo.FindByID(ctx, "")

		require.Nil(t, user)
		require.ErrorIs(t, err, entities.ErrUserNotFound)

		err = mock.ExpectationsWereMet()
		require.NoError(t, err)
	})
}
