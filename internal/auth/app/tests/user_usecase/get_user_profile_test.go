package userusecase_test

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"gogetnote/internal/auth/app"
	"gogetnote/internal/auth/domain/entities"
)

const (
	ErrCreatingUser       = "error creating user"
	ErrFindingUserByID    = "error finding user by ID"
	ErrFindingUserByEmail = "error finding user by email"
	ErrUpdatingUser       = "error updating user"
	ErrDeletingUser       = "error deleting user"
)

type mockUserRepository struct {
	mock.Mock
}

func (m *mockUserRepository) Create(ctx context.Context, user *entities.User) (*entities.User, error) {
	args := m.Called(ctx, user)
	if args.Get(0) == nil {
		return nil, fmt.Errorf("%s: %w", ErrCreatingUser, args.Error(1))
	}
	if args.Error(1) != nil {
		return args.Get(0).(*entities.User), fmt.Errorf("%s: %w", ErrCreatingUser, args.Error(1))
	}
	return args.Get(0).(*entities.User), nil
}

func (m *mockUserRepository) FindByID(ctx context.Context, id string) (*entities.User, error) {
	args := m.Called(ctx, id)
	if args.Get(0) == nil {
		return nil, fmt.Errorf("%s: %w", ErrFindingUserByID, args.Error(1))
	}
	if args.Error(1) != nil {
		return args.Get(0).(*entities.User), fmt.Errorf("%s: %w", ErrFindingUserByID, args.Error(1))
	}
	return args.Get(0).(*entities.User), nil
}

func (m *mockUserRepository) FindByEmail(ctx context.Context, email string) (*entities.User, error) {
	args := m.Called(ctx, email)
	if args.Get(0) == nil {
		return nil, fmt.Errorf("%s: %w", ErrFindingUserByEmail, args.Error(1))
	}
	if args.Error(1) != nil {
		return args.Get(0).(*entities.User), fmt.Errorf("%s: %w", ErrFindingUserByEmail, args.Error(1))
	}
	return args.Get(0).(*entities.User), nil
}

func (m *mockUserRepository) Update(ctx context.Context, user *entities.User) (*entities.User, error) {
	args := m.Called(ctx, user)
	if args.Get(0) == nil {
		return nil, fmt.Errorf("%s: %w", ErrUpdatingUser, args.Error(1))
	}
	if args.Error(1) != nil {
		return args.Get(0).(*entities.User), fmt.Errorf("%s: %w", ErrUpdatingUser, args.Error(1))
	}
	return args.Get(0).(*entities.User), nil
}

func (m *mockUserRepository) Delete(ctx context.Context, id string) error {
	args := m.Called(ctx, id)
	return fmt.Errorf("%s: %w", ErrDeletingUser, args.Error(0))
}

var ErrDatabaseConnection = errors.New("database connection error")

func TestGetUserProfile(t *testing.T) {
	mockRepo := new(mockUserRepository)
	useCase := app.NewUserUseCase(mockRepo)
	ctx := context.Background()

	testUser := &entities.User{
		ID:           "test-user-id",
		Email:        "test@example.com",
		Username:     "testuser",
		PasswordHash: "hashed_password",
		CreatedAt:    time.Now(),
		UpdatedAt:    time.Now(),
	}

	tests := []struct {
		name           string
		userID         string
		mockSetup      func()
		expectedUser   *entities.User
		expectedErrMsg string
		expectedErr    error
	}{
		{
			name:   "success case - user found",
			userID: "test-user-id",
			mockSetup: func() {
				mockRepo.On("FindByID", mock.Anything, "test-user-id").Return(testUser, nil).Once()
			},
			expectedUser: testUser,
			expectedErr:  nil,
		},
		{
			name:   "error case - empty user ID",
			userID: "",
			mockSetup: func() {
			},
			expectedUser:   nil,
			expectedErrMsg: "validating user ID",
			expectedErr:    entities.ErrEmptyUserID,
		},
		{
			name:   "error case - user not found",
			userID: "nonexistent-user-id",
			mockSetup: func() {
				mockRepo.On("FindByID", mock.Anything, "nonexistent-user-id").Return(nil, entities.ErrUserNotFound).Once()
			},
			expectedUser:   nil,
			expectedErrMsg: "fetching user profile",
			expectedErr:    entities.ErrUserNotFound,
		},
		{
			name:   "error case - repository error",
			userID: "error-user-id",
			mockSetup: func() {
				mockRepo.On("FindByID", mock.Anything, "error-user-id").Return(nil, ErrDatabaseConnection).Once()
			},
			expectedUser:   nil,
			expectedErrMsg: "fetching user profile",
			expectedErr:    ErrDatabaseConnection,
		},
	}

	for _, ttt := range tests {
		t.Run(ttt.name, func(t *testing.T) {
			ttt.mockSetup()

			user, err := useCase.GetUserProfile(ctx, ttt.userID)

			if ttt.expectedErr != nil {
				require.Error(t, err)
				assert.Contains(t, err.Error(), ttt.expectedErrMsg)

				if errors.Is(err, entities.ErrEmptyUserID) || errors.Is(err, entities.ErrUserNotFound) {
					require.ErrorIs(t, err, ttt.expectedErr)
				}
				assert.Nil(t, user)
			} else {
				require.NoError(t, err)
				assert.Equal(t, ttt.expectedUser, user)
			}

			mockRepo.AssertExpectations(t)
		})
	}
}
