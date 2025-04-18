package authusecase_test

import (
	"context"
	"time"

	"github.com/stretchr/testify/mock"

	"gogetnote/internal/auth/domain/entities"
	"gogetnote/internal/auth/domain/services"
)

type mockUserRepository struct {
	mock.Mock
}

func (m *mockUserRepository) Create(ctx context.Context, user *entities.User) (*entities.User, error) {
	args := m.Called(ctx, user)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*entities.User), args.Error(1)
}

func (m *mockUserRepository) FindByID(ctx context.Context, id string) (*entities.User, error) {
	args := m.Called(ctx, id)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*entities.User), args.Error(1)
}

func (m *mockUserRepository) FindByEmail(ctx context.Context, email string) (*entities.User, error) {
	args := m.Called(ctx, email)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*entities.User), args.Error(1)
}

func (m *mockUserRepository) Update(ctx context.Context, user *entities.User) (*entities.User, error) {
	args := m.Called(ctx, user)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*entities.User), args.Error(1)
}

func (m *mockUserRepository) Delete(ctx context.Context, id string) error {
	args := m.Called(ctx, id)
	return args.Error(0)
}

type mockTokenRepository struct {
	mock.Mock
}

func (m *mockTokenRepository) StoreRefreshToken(ctx context.Context, token *services.RefreshToken) error {
	return m.Called(ctx, token).Error(0)
}

func (m *mockTokenRepository) FindByToken(ctx context.Context, token string) (*services.RefreshToken, error) {
	args := m.Called(ctx, token)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*services.RefreshToken), args.Error(1)
}

func (m *mockTokenRepository) RevokeToken(ctx context.Context, token string) error {
	return m.Called(ctx, token).Error(0)
}

func (m *mockTokenRepository) RevokeAllUserTokens(ctx context.Context, userID string) error {
	return m.Called(ctx, userID).Error(0)
}

func (m *mockTokenRepository) CleanupExpiredTokens(ctx context.Context) error {
	return m.Called(ctx).Error(0)
}

func (m *mockTokenRepository) FindUserTokens(ctx context.Context, userID string) ([]*services.RefreshToken, error) {
	args := m.Called(ctx, userID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]*services.RefreshToken), args.Error(1)
}

type mockPasswordService struct {
	mock.Mock
}

func (m *mockPasswordService) Hash(ctx context.Context, password string) (string, error) {
	args := m.Called(ctx, password)
	return args.String(0), args.Error(1)
}

func (m *mockPasswordService) Verify(ctx context.Context, password, hash string) (bool, error) {
	args := m.Called(ctx, password, hash)
	return args.Bool(0), args.Error(1)
}

type mockTokenService struct {
	mock.Mock
}

func (m *mockTokenService) GenerateAccessToken(ctx context.Context, userID, username string) (string, time.Time, error) {
	args := m.Called(ctx, userID, username)
	return args.String(0), args.Get(1).(time.Time), args.Error(2)
}

func (m *mockTokenService) GenerateRefreshToken(ctx context.Context, userID string) (string, time.Time, error) {
	args := m.Called(ctx, userID)
	return args.String(0), args.Get(1).(time.Time), args.Error(2)
}

func (m *mockTokenService) ValidateAccessToken(ctx context.Context, token string) (string, error) {
	args := m.Called(ctx, token)
	return args.String(0), args.Error(1)
}
