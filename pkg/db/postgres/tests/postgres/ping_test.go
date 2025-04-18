package postgres_test

import (
	"context"
	"fmt"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"gogetnote/pkg/db/postgres"
	"gogetnote/pkg/logger"
)

const (
	msgPingAfterClose          = "ping should fail after connection is closed"
	msgInitialPingSuccess      = "initial ping should succeed"
	msgSkipTestDBFailed        = "skipping test as database connection failed"
	msgPingSuccessful          = "ping should succeed with working database connection"
	msgConnectionInvalid       = "connection to invalid database should fail"
	msgDBNotCreatedWithInvalid = "database should not be created with invalid connection"
	msgSkipNoPostgres          = "skipping test as no Postgres database is available"

	defaultPostgresDSN = "postgres://postgres:postgres@localhost:5432/postgres?sslmode=disable"
	// #nosec G101
	invalidPostgresDSN = "postgres://wrong:wrong@nonexistenthost:5432/nonexistentdb?sslmode=disable"
)

type MockPingPool struct {
	mock.Mock
}

func (m *MockPingPool) Ping(ctx context.Context) error {
	args := m.Called(ctx)
	if err := args.Error(0); err != nil {
		return fmt.Errorf("mock ping error: %w", err)
	}
	return nil
}

func (m *MockPingPool) Close() {}

func TestDatabasePing(t *testing.T) {
	err := logger.InitGlobalLoggerWithLevel(logger.Development, "info")
	require.NoError(t, err)

	ctx := context.Background()

	t.Run("Integration - Ping with real database", func(t *testing.T) {
		realDB, err := postgres.New(ctx, defaultPostgresDSN, 1, 2)
		if err != nil {
			t.Skip(msgSkipTestDBFailed)
		}
		defer realDB.Close(ctx)

		err = realDB.Ping(ctx)
		assert.NoError(t, err, msgPingSuccessful)
	})

	t.Run("With unavailable database", func(t *testing.T) {
		// #nosec G101
		db, err := postgres.New(ctx, invalidPostgresDSN, 1, 2)

		require.Error(t, err, msgConnectionInvalid)
		assert.Nil(t, db, msgDBNotCreatedWithInvalid)
	})

	t.Run("With working connection that later fails", func(t *testing.T) {
		tempPool, err := pgxpool.New(ctx, defaultPostgresDSN)
		if err != nil {
			t.Skip(msgSkipNoPostgres)
		}
		tempPool.Close()

		realDB, err := postgres.New(ctx, defaultPostgresDSN, 1, 2)
		if err != nil {
			t.Skip(msgSkipTestDBFailed)
		}

		err = realDB.Ping(ctx)
		require.NoError(t, err, msgInitialPingSuccess)

		realDB.Close(ctx)

		err = realDB.Ping(ctx)
		assert.Error(t, err, msgPingAfterClose)
	})
}
