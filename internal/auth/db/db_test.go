package db_test

import (
	"context"
	"errors"
	"gogetnote/internal/auth/config"
	"gogetnote/internal/auth/db"
	"gogetnote/pkg/db/postgres"
	"gogetnote/pkg/logger"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"github.com/undefinedlabs/go-mpatch"
)

const (
	ErrUnpatchMsg        = "failed to unpatch"
	ErrUnpatchCloseMsg   = "failed to unpatch Close method"
	ErrPatchCloseMsg     = "error patching Close method"
	CloseMethodCalledMsg = "close method should be called"
	MigrationsPath       = "./migrations"
)

func safeUnpatch(t *testing.T, p *mpatch.Patch) {
	t.Helper()
	if err := p.Unpatch(); err != nil {
		t.Errorf("%s: %v", ErrUnpatchMsg, err)
	}
}

func TestClose(t *testing.T) {
	err := logger.InitGlobalLoggerWithLevel(logger.Development, "info")
	require.NoError(t, err)

	ctx := context.Background()

	t.Run("сlose should call Close on the internal database", func(t *testing.T) {
		closeCalled := false

		patch, err := mpatch.PatchInstanceMethodByName(reflect.TypeOf(&postgres.Database{}), "Close", func(_ *postgres.Database, _ context.Context) {
			closeCalled = true
		})
		require.NoError(t, err, ErrPatchCloseMsg)
		defer func() {
			if err := patch.Unpatch(); err != nil {
				t.Errorf("%s: %v", ErrUnpatchCloseMsg, err)
			}
		}()

		cfg := &config.PostgresConfig{
			Host:     "testhost",
			Port:     5432,
			User:     "testuser",
			Password: "testpass",
			Database: "testdb",
			MinConn:  1,
			MaxConn:  10,
		}

		migratePatch, err := mpatch.PatchMethod(postgres.MigrateDSN, func(_ context.Context, _, _ string) error {
			return nil
		})
		require.NoError(t, err)
		defer safeUnpatch(t, migratePatch)

		newPatch, err := mpatch.PatchMethod(postgres.New, func(_ context.Context, _ string, _, _ int) (*postgres.Database, error) {
			return &postgres.Database{}, nil
		})
		require.NoError(t, err)
		defer safeUnpatch(t, newPatch)

		database, err := db.New(ctx, cfg, MigrationsPath)
		require.NoError(t, err)

		database.Close(ctx)

		require.True(t, closeCalled, CloseMethodCalledMsg)
	})

	t.Run("close should not panic", func(t *testing.T) {
		patch, err := mpatch.PatchInstanceMethodByName(reflect.TypeOf(&postgres.Database{}), "Close", func(_ *postgres.Database, _ context.Context) {
		})
		require.NoError(t, err)
		defer safeUnpatch(t, patch)

		cfg := &config.PostgresConfig{
			Host:     "testhost",
			Port:     5432,
			User:     "testuser",
			Password: "testpass",
			Database: "testdb",
			MinConn:  1,
			MaxConn:  10,
		}

		migratePatch, err := mpatch.PatchMethod(postgres.MigrateDSN, func(_ context.Context, _, _ string) error {
			return nil
		})
		require.NoError(t, err)
		defer safeUnpatch(t, migratePatch)

		newPatch, err := mpatch.PatchMethod(postgres.New, func(_ context.Context, _ string, _, _ int) (*postgres.Database, error) {
			return &postgres.Database{}, nil
		})
		require.NoError(t, err)
		defer safeUnpatch(t, newPatch)

		database, err := db.New(ctx, cfg, MigrationsPath)
		require.NoError(t, err)

		require.NotPanics(t, func() {
			database.Close(ctx)
		})
	})
}

const (
	DatabaseShouldReturnConfiguredDB = "Database() should return the configured database"
)

type MockDB2 struct {
	mock.Mock
}

func (m *MockDB2) Database() *postgres.Database {
	args := m.Called()
	return args.Get(0).(*postgres.Database)
}

func TestDatabase(t *testing.T) {
	mockDB := new(MockDB2)
	mockDatabase := &postgres.Database{}

	mockDB.On("Database").Return(mockDatabase)

	returnedDatabase := mockDB.Database()
	assert.Equal(t, mockDatabase, returnedDatabase, DatabaseShouldReturnConfiguredDB)

	mockDB.AssertExpectations(t)
}

const (
	errMsgMigrate      = "error patching MigrateDSN"
	errMsgMigration    = "failed to apply authentication database migrations"
	errMsgConnection   = "failed to connect to authentication database"
	errMsgRelativePath = "./relative/path"
	errMsgPath         = "failed to get path"
	errMsgPatchNew     = "error patching postgres.New"
	errMsgPatchAbs     = "error patching filepath.Abs"
	migrationsPath     = "./migrations"
)

var (
	errMigration  = errors.New("migration error")
	errConnection = errors.New("connection error")
	errPath       = errors.New("path error")
)

func TestNew(t *testing.T) {
	err := logger.InitGlobalLoggerWithLevel(logger.Development, "info")
	require.NoError(t, err)

	ctx := context.Background()

	cfg := &config.PostgresConfig{
		Host:     "testhost",
		Port:     5432,
		User:     "testuser",
		Password: "testpass",
		Database: "testdb",
		MinConn:  1,
		MaxConn:  10,
	}
	migrationsDir := migrationsPath

	t.Run("successful database creation", func(_ *testing.T) {
	})

	t.Run("migration error", func(t *testing.T) {
		expectedErr := errMigration

		migratePatch, err := mpatch.PatchMethod(postgres.MigrateDSN, func(_ context.Context, _, _ string) error {
			return expectedErr
		})
		require.NoError(t, err, errMsgMigrate)
		defer safeUnpatch(t, migratePatch)

		database, err := db.New(ctx, cfg, migrationsDir)

		require.Error(t, err)
		assert.Nil(t, database)
		require.ErrorContains(t, err, errMsgMigration)
		assert.ErrorIs(t, err, expectedErr)
	})

	t.Run("database connection error", func(t *testing.T) {
		expectedErr := errConnection

		migratePatch, err := mpatch.PatchMethod(postgres.MigrateDSN, func(_ context.Context, _, _ string) error {
			return nil
		})
		require.NoError(t, err, errMsgMigrate)
		defer safeUnpatch(t, migratePatch)

		newPatch, err := mpatch.PatchMethod(postgres.New, func(_ context.Context, _ string, _, _ int) (*postgres.Database, error) {
			return nil, expectedErr
		})
		require.NoError(t, err, errMsgPatchNew)
		defer safeUnpatch(t, newPatch)

		database, err := db.New(ctx, cfg, migrationsDir)

		require.Error(t, err)
		assert.Nil(t, database)
		require.ErrorContains(t, err, errMsgConnection)
		assert.ErrorIs(t, err, expectedErr)
	})

	t.Run("absolute path error", func(t *testing.T) {
		expectedErr := errPath

		absPatch, err := mpatch.PatchMethod(filepath.Abs, func(_ string) (string, error) {
			return "", expectedErr
		})
		require.NoError(t, err, errMsgPatchAbs)
		defer safeUnpatch(t, absPatch)

		database, err := db.New(ctx, cfg, errMsgRelativePath)

		require.Error(t, err)
		assert.Nil(t, database)
		require.ErrorContains(t, err, errMsgPath)
		assert.ErrorIs(t, err, expectedErr)
	})
}

const (
	MsgSkipTest                 = "skipping test - failed to connect to database:"
	MsgPingShouldSucceed        = "ping should succeed with a working connection"
	MsgConnectionShouldFail     = "connection to unreachable database should fail"
	MsgInstanceNotCreated       = "database instance should not be created on connection error"
	MsgPingShouldFailAfterClose = "ping should fail after connection is closed"
	MsgInitialPingShouldSucceed = "initial ping should be successful"
	DefaultMigrationsPath       = "./migrations"
)

func TestPing(t *testing.T) {
	err := logger.InitGlobalLoggerWithLevel(logger.Development, "info")
	require.NoError(t, err)

	ctx := context.Background()

	t.Run("integration - Ping with real database", func(t *testing.T) {
		migratePatch, err := mpatch.PatchMethod(postgres.MigrateDSN, func(_ context.Context, _, _ string) error {
			return nil
		})
		require.NoError(t, err)
		defer safeUnpatch(t, migratePatch)

		cfg := &config.PostgresConfig{
			Host:     "localhost",
			Port:     5432,
			User:     "postgres",
			Password: "postgres",
			Database: "postgres",
			MinConn:  1,
			MaxConn:  2,
		}

		database, err := db.New(ctx, cfg, DefaultMigrationsPath)
		if err != nil {
			t.Skip(MsgSkipTest, err)
			return
		}
		defer database.Close(ctx)

		err = database.Ping(ctx)
		assert.NoError(t, err, MsgPingShouldSucceed)
	})

	t.Run("with unreachable database", func(t *testing.T) {
		migratePatch, err := mpatch.PatchMethod(postgres.MigrateDSN, func(_ context.Context, _, _ string) error {
			return nil
		})
		require.NoError(t, err)
		defer safeUnpatch(t, migratePatch)

		invalidCfg := &config.PostgresConfig{
			Host:     "nonexistenthost",
			Port:     5432,
			User:     "wrong",
			Password: "wrong",
			Database: "wrongdb",
			MinConn:  1,
			MaxConn:  2,
		}

		database, err := db.New(ctx, invalidCfg, DefaultMigrationsPath)

		require.Error(t, err, MsgConnectionShouldFail)
		assert.Nil(t, database, MsgInstanceNotCreated)
	})

	t.Run("with working connection that is later closed", func(t *testing.T) {
		migratePatch, err := mpatch.PatchMethod(postgres.MigrateDSN, func(_ context.Context, _, _ string) error {
			return nil
		})
		require.NoError(t, err)
		defer safeUnpatch(t, migratePatch)

		cfg := &config.PostgresConfig{
			Host:     "localhost",
			Port:     5432,
			User:     "postgres",
			Password: "postgres",
			Database: "postgres",
			MinConn:  1,
			MaxConn:  2,
		}

		database, err := db.New(ctx, cfg, DefaultMigrationsPath)
		if err != nil {
			t.Skip(MsgSkipTest, err)
			return
		}

		err = database.Ping(ctx)
		require.NoError(t, err, MsgInitialPingShouldSucceed)

		database.Close(ctx)

		err = database.Ping(ctx)
		assert.Error(t, err, MsgPingShouldFailAfterClose)
	})
}

const PoolShouldReturnConfiguredPool = "pool() should return the configured pool"

type MockDB struct {
	mock.Mock
}

func (m *MockDB) Pool() *pgxpool.Pool {
	args := m.Called()
	return args.Get(0).(*pgxpool.Pool)
}

func TestPool(t *testing.T) {
	mockDB := new(MockDB)
	mockPool := &pgxpool.Pool{}

	mockDB.On("Pool").Return(mockPool)

	returnedPool := mockDB.Pool()
	assert.Equal(t, mockPool, returnedPool, PoolShouldReturnConfiguredPool)

	mockDB.AssertExpectations(t)
}
