package db_test

import (
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

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
	assert.Equal(t, mockPool, returnedPool, "Pool() should return the configured pool")

	mockDB.AssertExpectations(t)
}
