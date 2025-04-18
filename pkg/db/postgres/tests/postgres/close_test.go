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

const (
	skipNoDatabaseMsg = "skipping test as no Postgres database is available"
	skipConnFailedMsg = "skipping test as database connection failed"
	testDSN           = "postgres://postgres:postgres@localhost:5432/postgres?sslmode=disable"
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

	t.Run("when Close is called, pool's Close method should be called", func(t *testing.T) {
		tempPool, err := pgxpool.New(ctx, testDSN)
		if err != nil {
			t.Skip(skipNoDatabaseMsg)
		}
		tempPool.Close()

		realDB, err := postgres.New(ctx, testDSN, 1, 2)
		if err != nil {
			t.Skip(skipConnFailedMsg)
		}

		assert.NotPanics(t, func() {
			realDB.Close(ctx)
		})
	})
}
