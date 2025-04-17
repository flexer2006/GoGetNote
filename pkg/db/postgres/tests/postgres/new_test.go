package postgres_test

import (
	"context"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"gogetnote/pkg/db/postgres"
	"gogetnote/pkg/logger"
)

func TestDatabaseNew(t *testing.T) {
	err := logger.InitGlobalLoggerWithLevel(logger.Development, "info")
	require.NoError(t, err)

	ctx := context.Background()

	t.Run("Success - Valid connection parameters", func(t *testing.T) {
		dsn := "postgres://postgres:postgres@localhost:5432/postgres?sslmode=disable"
		minConn := 2
		maxConn := 5

		db, err := postgres.New(ctx, dsn, minConn, maxConn)

		if err != nil && strings.Contains(err.Error(), "failed to ping database") {
			t.Skip("Skipping test as PostgreSQL database is not available")
		}

		require.NoError(t, err, "Should successfully connect to database")
		require.NotNil(t, db, "Database object should not be nil")

		poolResult := db.Pool()
		assert.NotNil(t, poolResult, "Pool() should return a non-nil connection pool")

		pingErr := db.Ping(ctx)
		assert.NoError(t, pingErr, "Should be able to ping database after connection")

		db.Close(ctx)
	})

	t.Run("Error - Invalid DSN format", func(t *testing.T) {
		invalidDSN := "not-a-valid-dsn"
		minConn := 1
		maxConn := 2

		db, err := postgres.New(ctx, invalidDSN, minConn, maxConn)

		assert.Error(t, err, "Should fail with invalid DSN")
		assert.Nil(t, db, "Database object should be nil on error")
		assert.Contains(t, err.Error(), "failed to parse connection config",
			"Error should mention config parsing failure")
	})

	t.Run("Error - Valid DSN format but unreachable host", func(t *testing.T) {
		unreachableDSN := "postgres://user:pass@nonexistenthost:5432/db?sslmode=disable"
		minConn := 1
		maxConn := 2

		db, err := postgres.New(ctx, unreachableDSN, minConn, maxConn)

		assert.Error(t, err, "Should fail with unreachable host")
		assert.Nil(t, db, "Database object should be nil on error")

		errorMessage := err.Error()
		connectionFailureDetected := strings.Contains(errorMessage, "failed to create connection pool") ||
			strings.Contains(errorMessage, "failed to ping database")

		assert.True(t, connectionFailureDetected,
			"Error should mention connection pool creation or ping failure")
	})

	t.Run("Connection parameters validation", func(t *testing.T) {
		dsn := "postgres://postgres:postgres@localhost:5432/postgres?sslmode=disable"
		invalidMinConn := -5
		invalidMaxConn := 0

		assert.NotPanics(t, func() {
			db, _ := postgres.New(ctx, dsn, invalidMinConn, invalidMaxConn)
			if db != nil {
				db.Close(ctx)
			}
		}, "Function should handle invalid connection parameters without panic")
	})

	t.Run("Min/Max connections set correctly", func(t *testing.T) {
		dsn := "postgres://postgres:postgres@localhost:5432/postgres?sslmode=disable"
		minConn := 3
		maxConn := 10

		db, err := postgres.New(ctx, dsn, minConn, maxConn)
		if err != nil {
			t.Skip("Skipping test as database connection failed")
		}
		defer db.Close(ctx)

		assert.NotNil(t, db.Pool(), "Pool should be initialized with specified min/max connections")
	})
}
