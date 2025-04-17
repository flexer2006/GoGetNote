package postgres_test

import (
	"context"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"gogetnote/pkg/db/postgres"
	"gogetnote/pkg/logger"
)

type MockPingPool struct {
	mock.Mock
}

func (m *MockPingPool) Ping(ctx context.Context) error {
	args := m.Called(ctx)
	return args.Error(0)
}

func (m *MockPingPool) Close() {}

func TestDatabasePing(t *testing.T) {
	err := logger.InitGlobalLoggerWithLevel(logger.Development, "info")
	require.NoError(t, err)

	ctx := context.Background()

	t.Run("Integration - Ping with real database", func(t *testing.T) {
		tempDSN := "postgres://postgres:postgres@localhost:5432/postgres?sslmode=disable"

		realDB, err := postgres.New(ctx, tempDSN, 1, 2)
		if err != nil {
			t.Skip("Skipping test as database connection failed")
		}
		defer realDB.Close(ctx)

		err = realDB.Ping(ctx)
		assert.NoError(t, err, "Ping should succeed with working database connection")
	})

	t.Run("With unavailable database", func(t *testing.T) {
		invalidDSN := "postgres://wrong:wrong@nonexistenthost:5432/nonexistentdb?sslmode=disable"

		db, err := postgres.New(ctx, invalidDSN, 1, 2)

		assert.Error(t, err, "Connection to invalid database should fail")
		assert.Nil(t, db, "Database should not be created with invalid connection")
	})

	t.Run("With working connection that later fails", func(t *testing.T) {
		tempDSN := "postgres://postgres:postgres@localhost:5432/postgres?sslmode=disable"

		tempPool, err := pgxpool.New(ctx, tempDSN)
		if err != nil {
			t.Skip("Skipping test as no PostgreSQL database is available")
		}
		tempPool.Close()

		realDB, err := postgres.New(ctx, tempDSN, 1, 2)
		if err != nil {
			t.Skip("Skipping test as database connection failed")
		}

		err = realDB.Ping(ctx)
		assert.NoError(t, err, "Initial ping should succeed")

		realDB.Close(ctx)

		err = realDB.Ping(ctx)
		assert.Error(t, err, "Ping should fail after connection is closed")
	})
}
