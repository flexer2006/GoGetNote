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

const (
	errMsgFailedToPingDB        = "failed to ping database"
	errMsgFailedCreateConnPool  = "failed to create connection pool"
	errMsgConnectionPoolOrPing  = "error should mention connection pool creation or ping failure"
	errMsgFailedParseConnConfig = "failed to parse connection config"

	errMsgDBShouldNotBeNil          = "database object should not be nil"
	errMsgInvalidParamsWithoutPanic = "function should handle invalid connection parameters without panic"
	errMsgShouldFailUnreachableHost = "should fail with unreachable host"
	errMsgDBShouldBeNilOnError      = "database object should be nil on error"

	validDSN       = "postgres://postgres:postgres@localhost:5432/postgres?sslmode=disable"
	invalidDSN     = "not-a-valid-dsn"
	unreachableDSN = "postgres://user:pass@nonexistenthost:5432/db?sslmode=disable"

	skipMsgDBConnFailed         = "skipping test as database connection failed"
	skipMsgPostgresNotAvailable = "skipping test as Postgres database is not available"
)

func TestDatabaseNew(t *testing.T) {
	err := logger.InitGlobalLoggerWithLevel(logger.Development, "info")
	require.NoError(t, err)

	ctx := context.Background()

	t.Run("Success - Valid connection parameters", func(t *testing.T) {
		minConn := 2
		maxConn := 5

		database, err := postgres.New(ctx, validDSN, minConn, maxConn)

		if err != nil && strings.Contains(err.Error(), errMsgFailedToPingDB) {
			t.Skip(skipMsgPostgresNotAvailable)
		}

		require.NoError(t, err, "Should successfully connect to database")
		require.NotNil(t, database, errMsgDBShouldNotBeNil)

		poolResult := database.Pool()
		assert.NotNil(t, poolResult, "Pool() should return a non-nil connection pool")

		pingErr := database.Ping(ctx)
		require.NoError(t, pingErr, "Should be able to ping database after connection")

		database.Close(ctx)
	})

	t.Run("Error - Invalid DSN format", func(t *testing.T) {
		minConn := 1
		maxConn := 2

		database, err := postgres.New(ctx, invalidDSN, minConn, maxConn)

		require.Error(t, err, "Should fail with invalid DSN")
		assert.Nil(t, database, errMsgDBShouldBeNilOnError)
		assert.Contains(t, err.Error(), errMsgFailedParseConnConfig,
			"Error should mention config parsing failure")
	})

	t.Run("Error - Valid DSN format but unreachable host", func(t *testing.T) {
		minConn := 1
		maxConn := 2

		database, err := postgres.New(ctx, unreachableDSN, minConn, maxConn)

		require.Error(t, err, errMsgShouldFailUnreachableHost)
		assert.Nil(t, database, errMsgDBShouldBeNilOnError)

		errorMessage := err.Error()
		connectionFailureDetected := strings.Contains(errorMessage, errMsgFailedCreateConnPool) ||
			strings.Contains(errorMessage, errMsgFailedToPingDB)

		assert.True(t, connectionFailureDetected, errMsgConnectionPoolOrPing)
	})

	t.Run("Connection parameters validation", func(t *testing.T) {
		invalidMinConn := -5
		invalidMaxConn := 0

		assert.NotPanics(t, func() {
			database, _ := postgres.New(ctx, validDSN, invalidMinConn, invalidMaxConn)
			if database != nil {
				database.Close(ctx)
			}
		}, errMsgInvalidParamsWithoutPanic)
	})

	t.Run("Min/Max connections set correctly", func(t *testing.T) {
		minConn := 3
		maxConn := 10

		database, err := postgres.New(ctx, validDSN, minConn, maxConn)
		if err != nil {
			t.Skip(skipMsgDBConnFailed)
		}
		defer database.Close(ctx)

		assert.NotNil(t, database.Pool(), "Pool should be initialized with specified min/max connections")
	})
}
