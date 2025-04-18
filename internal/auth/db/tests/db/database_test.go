package db_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"

	"gogetnote/pkg/db/postgres"
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
	assert.Equal(t, mockDatabase, returnedDatabase, "Database() should return the configured database")

	mockDB.AssertExpectations(t)
}
