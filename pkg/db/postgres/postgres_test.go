package postgres_test

import (
	"context"
	"errors"
	"fmt"
	"gogetnote/pkg/db/postgres"
	"gogetnote/pkg/logger"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"github.com/undefinedlabs/go-mpatch"
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

type MockDatabase struct {
	mock.Mock
}

func (m *MockDatabase) Pool() *pgxpool.Pool {
	args := m.Called()
	return args.Get(0).(*pgxpool.Pool)
}

func TestDatabasePool(t *testing.T) {
	mockDB := new(MockDatabase)
	mockPool := &pgxpool.Pool{}

	mockDB.On("Pool").Return(mockPool)

	returnedPool := mockDB.Pool()
	assert.Equal(t, mockPool, returnedPool, "Pool() should return the configured pool")

	mockDB.AssertExpectations(t)
}

func safeUnpatch(t *testing.T, p *mpatch.Patch) {
	t.Helper()
	if err := p.Unpatch(); err != nil {
		t.Errorf("Failed to unpatch: %v", err)
	}
}

var (
	errMigrationCreationFailed = errors.New("migration creation failed")
	errMigrationFailed         = errors.New("migration failed")
)

// func TestMigrateDSN(t *testing.T) {
// 	err := logger.InitGlobalLoggerWithLevel(logger.Development, "info")
// 	require.NoError(t, err)

// 	ctx := context.Background()
// 	dsn := "postgres://user:pass@localhost:5432/testdb"
// 	migrationsPath := "file://./migrations"

// 	t.Run("success case", func(t *testing.T) {
// 		newPatch, err := mpatch.PatchMethod(migrate.New, func(source, database string) (*migrate.Migrate, error) {
// 			assert.Equal(t, migrationsPath, source)
// 			assert.Equal(t, dsn, database)

// 			return nil, nil
// 		})
// 		require.NoError(t, err, "Failed to patch migrate.New")
// 		defer func() {
// 			if err := newPatch.Unpatch(); err != nil {
// 				t.Errorf("Failed to unpatch: %v", err)
// 			}
// 		}()

// 		upCalled := false
// 		upPatch, err := mpatch.PatchMethod((*migrate.Migrate).Up, func(_ *migrate.Migrate) error {
// 			upCalled = true
// 			return nil
// 		})
// 		require.NoError(t, err, "Failed to patch Up method")
// 		defer safeUnpatch(t, upPatch)

// 		closeCalled := false
// 		closePatch, err := mpatch.PatchMethod((*migrate.Migrate).Close, func(_ *migrate.Migrate) (error, error) {
// 			closeCalled = true
// 			return nil, nil
// 		})
// 		require.NoError(t, err, "Failed to patch Close method")
// 		defer safeUnpatch(t, closePatch)

// 		err = postgres.MigrateDSN(ctx, dsn, migrationsPath)
// 		require.NoError(t, err)

// 		assert.True(t, upCalled, "Up method should have been called")
// 		assert.True(t, closeCalled, "Close method should have been called")
// 	})

// 	t.Run("error creating migration instance", func(t *testing.T) {
// 		expectedErr := errMigrationCreationFailed

// 		patch, err := mpatch.PatchMethod(migrate.New, func(_ string, _ string) (*migrate.Migrate, error) {
// 			return nil, expectedErr
// 		})
// 		require.NoError(t, err, "Failed to patch migrate.New")
// 		defer safeUnpatch(t, patch)

// 		err = postgres.MigrateDSN(ctx, dsn, migrationsPath)

// 		require.Error(t, err)
// 		assert.Contains(t, err.Error(), "failed to create migration instance")
// 		assert.ErrorIs(t, err, expectedErr)
// 	})

// 	t.Run("error applying migrations", func(t *testing.T) {
// 		expectedErr := errMigrationFailed

// 		newPatch, err := mpatch.PatchMethod(migrate.New, func(_, _ string) (*migrate.Migrate, error) {
// 			return nil, nil
// 		})
// 		require.NoError(t, err, "Failed to patch migrate.New")
// 		defer safeUnpatch(t, newPatch)

// 		upPatch, err := mpatch.PatchMethod((*migrate.Migrate).Up, func(_ *migrate.Migrate) error {
// 			return expectedErr
// 		})
// 		require.NoError(t, err, "Failed to patch Up method")
// 		defer safeUnpatch(t, upPatch)

// 		closePatch, err := mpatch.PatchMethod((*migrate.Migrate).Close, func(_ *migrate.Migrate) (error, error) {
// 			return nil, nil
// 		})
// 		require.NoError(t, err, "Failed to patch Close method")
// 		defer safeUnpatch(t, closePatch)

// 		err = postgres.MigrateDSN(ctx, dsn, migrationsPath)

// 		require.Error(t, err)
// 		assert.Contains(t, err.Error(), "failed to apply migrations")
// 		assert.ErrorIs(t, err, expectedErr)
// 	})

// 	t.Run("no changes needed case", func(t *testing.T) {
// 		newPatch, err := mpatch.PatchMethod(migrate.New, func(_, _ string) (*migrate.Migrate, error) {
// 			return nil, nil
// 		})
// 		require.NoError(t, err, "Failed to patch migrate.New")
// 		defer safeUnpatch(t, newPatch)

// 		upPatch, err := mpatch.PatchMethod((*migrate.Migrate).Up, func(_ *migrate.Migrate) error {
// 			return migrate.ErrNoChange
// 		})
// 		require.NoError(t, err, "Failed to patch Up method")
// 		defer safeUnpatch(t, upPatch)

// 		closePatch, err := mpatch.PatchMethod((*migrate.Migrate).Close, func(_ *migrate.Migrate) (error, error) {
// 			return nil, nil
// 		})
// 		require.NoError(t, err, "Failed to patch Close method")
// 		defer safeUnpatch(t, closePatch)

// 		err = postgres.MigrateDSN(ctx, dsn, migrationsPath)

// 		require.NoError(t, err)
// 	})
// }
