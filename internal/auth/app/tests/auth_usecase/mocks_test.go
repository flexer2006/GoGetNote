package authusecase_test

import (
	"context"
	"fmt"
	"time"

	"github.com/stretchr/testify/mock"

	"gogetnote/internal/auth/domain/entities"
	"gogetnote/internal/auth/domain/services"
)

const (
	ErrCreateUser      = "failed to create user"
	ErrFindUserByID    = "failed to find user by ID"
	ErrFindUserByEmail = "failed to find user by email"
	ErrUserEmailLookup = "error while finding user by email"
	ErrUpdateUser      = "failed to update user"
	ErrUpdateUserProc  = "error while updating user"
	ErrDeleteUser      = "error when deleting user"
)

// nolint:gosec
const (
	ErrStoreRefreshToken   = "error when storing refresh token"
	ErrFindToken           = "error when searching for token"
	ErrGetToken            = "error when retrieving token"
	ErrRevokeToken         = "error when revoking token"
	ErrRevokeAllUserTokens = "error when revoking all user tokens"
	ErrCleanupTokens       = "error when cleaning up expired tokens"
	ErrFindUserTokens      = "error when searching for user tokens"
	ErrGetUserTokens       = "error when retrieving user tokens"
)

type mockUserRepository struct {
	mock.Mock
}

func (m *mockUserRepository) Create(ctx context.Context, user *entities.User) (*entities.User, error) {
	args := m.Called(ctx, user)
	if args.Get(0) == nil {
		err := args.Error(1)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", ErrCreateUser, err)
		}
		return nil, nil
	}
	return args.Get(0).(*entities.User), nil
}

func (m *mockUserRepository) FindByID(ctx context.Context, id string) (*entities.User, error) {
	args := m.Called(ctx, id)
	if args.Get(0) == nil {
		err := args.Error(1)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", ErrFindUserByID, err)
		}
		return nil, nil
	}
	return args.Get(0).(*entities.User), nil
}

func (m *mockUserRepository) FindByEmail(ctx context.Context, email string) (*entities.User, error) {
	args := m.Called(ctx, email)
	if args.Get(0) == nil {
		err := args.Error(1)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", ErrFindUserByEmail, err)
		}
		return nil, nil
	}

	user := args.Get(0).(*entities.User)
	err := args.Error(1)
	if err != nil {
		return user, fmt.Errorf("%s: %w", ErrUserEmailLookup, err)
	}
	return user, nil
}

func (m *mockUserRepository) Update(ctx context.Context, user *entities.User) (*entities.User, error) {
	args := m.Called(ctx, user)
	if args.Get(0) == nil {
		err := args.Error(1)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", ErrUpdateUser, err)
		}
		return nil, nil
	}

	updatedUser := args.Get(0).(*entities.User)
	err := args.Error(1)
	if err != nil {
		return updatedUser, fmt.Errorf("%s: %w", ErrUpdateUserProc, err)
	}
	return updatedUser, nil
}

func (m *mockUserRepository) Delete(ctx context.Context, id string) error {
	args := m.Called(ctx, id)
	if err := args.Error(0); err != nil {
		return fmt.Errorf("%s: %w", ErrDeleteUser, err)
	}
	return nil
}

type mockTokenRepository struct {
	mock.Mock
}

func (m *mockTokenRepository) StoreRefreshToken(ctx context.Context, token *services.RefreshToken) error {
	err := m.Called(ctx, token).Error(0)
	if err != nil {
		return fmt.Errorf("%s: %w", ErrStoreRefreshToken, err)
	}
	return nil
}

func (m *mockTokenRepository) FindByToken(ctx context.Context, token string) (*services.RefreshToken, error) {
	args := m.Called(ctx, token)
	if args.Get(0) == nil {
		err := args.Error(1)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", ErrFindToken, err)
		}
		return nil, nil
	}
	err := args.Error(1)
	if err != nil {
		return args.Get(0).(*services.RefreshToken), fmt.Errorf("%s: %w", ErrGetToken, err)
	}
	return args.Get(0).(*services.RefreshToken), nil
}

func (m *mockTokenRepository) RevokeToken(ctx context.Context, token string) error {
	err := m.Called(ctx, token).Error(0)
	if err != nil {
		return fmt.Errorf("%s: %w", ErrRevokeToken, err)
	}
	return nil
}

func (m *mockTokenRepository) RevokeAllUserTokens(ctx context.Context, userID string) error {
	err := m.Called(ctx, userID).Error(0)
	if err != nil {
		return fmt.Errorf("%s: %w", ErrRevokeAllUserTokens, err)
	}
	return nil
}

func (m *mockTokenRepository) CleanupExpiredTokens(ctx context.Context) error {
	err := m.Called(ctx).Error(0)
	if err != nil {
		return fmt.Errorf("%s: %w", ErrCleanupTokens, err)
	}
	return nil
}

func (m *mockTokenRepository) FindUserTokens(ctx context.Context, userID string) ([]*services.RefreshToken, error) {
	args := m.Called(ctx, userID)
	if args.Get(0) == nil {
		err := args.Error(1)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", ErrFindUserTokens, err)
		}
		return nil, nil
	}
	err := args.Error(1)
	if err != nil {
		return args.Get(0).([]*services.RefreshToken), fmt.Errorf("%s: %w", ErrGetUserTokens, err)
	}
	return args.Get(0).([]*services.RefreshToken), nil
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
