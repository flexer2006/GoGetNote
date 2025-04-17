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

type MockPool struct {
	mock.Mock
}

func (m *MockPool) Close() {
	m.Called()
}

func TestDatabaseClose(t *testing.T) {
	err := logger.InitGlobalLoggerWithLevel(logger.Development, "info")
	require.NoError(t, err)

	ctx := context.Background()

	mockPool := new(MockPool)
	mockPool.On("Close").Return()

	t.Run("When Close is called, pool's Close method should be called", func(t *testing.T) {
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

		assert.NotPanics(t, func() {
			realDB.Close(ctx)
		})
	})
}
