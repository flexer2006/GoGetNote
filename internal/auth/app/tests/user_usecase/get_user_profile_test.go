package userusecase_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"gogetnote/internal/auth/app"
	"gogetnote/internal/auth/domain/entities"
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
			name:   "Success case - user found",
			userID: "test-user-id",
			mockSetup: func() {
				mockRepo.On("FindByID", mock.Anything, "test-user-id").Return(testUser, nil).Once()
			},
			expectedUser: testUser,
			expectedErr:  nil,
		},
		{
			name:   "Error case - empty user ID",
			userID: "",
			mockSetup: func() {
			},
			expectedUser:   nil,
			expectedErrMsg: "validating user ID",
			expectedErr:    entities.ErrEmptyUserID,
		},
		{
			name:   "Error case - user not found",
			userID: "nonexistent-user-id",
			mockSetup: func() {
				mockRepo.On("FindByID", mock.Anything, "nonexistent-user-id").Return(nil, entities.ErrUserNotFound).Once()
			},
			expectedUser:   nil,
			expectedErrMsg: "fetching user profile",
			expectedErr:    entities.ErrUserNotFound,
		},
		{
			name:   "Error case - repository error",
			userID: "error-user-id",
			mockSetup: func() {
				mockRepo.On("FindByID", mock.Anything, "error-user-id").Return(nil, errors.New("database connection error")).Once()
			},
			expectedUser:   nil,
			expectedErrMsg: "fetching user profile",
			expectedErr:    errors.New("database connection error"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.mockSetup()

			user, err := useCase.GetUserProfile(ctx, tt.userID)

			if tt.expectedErr != nil {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.expectedErrMsg)

				// Для предопределенных ошибок используем errors.Is
				if errors.Is(err, entities.ErrEmptyUserID) || errors.Is(err, entities.ErrUserNotFound) {
					assert.ErrorIs(t, err, tt.expectedErr)
				}
				assert.Nil(t, user)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tt.expectedUser, user)
			}

			mockRepo.AssertExpectations(t)
		})
	}
}
