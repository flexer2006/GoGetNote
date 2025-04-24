package grpc_test

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
	"google.golang.org/protobuf/types/known/emptypb"
	"google.golang.org/protobuf/types/known/timestamppb"

	grpcAdapter "gogetnote/internal/auth/adapters/grpc"
	"gogetnote/internal/auth/config"
	"gogetnote/internal/auth/domain/entities"
	"gogetnote/internal/auth/domain/services"
	authv1 "gogetnote/pkg/api/auth/v1"
	"gogetnote/pkg/logger"
)

func TestNew(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name      string
		cfg       *config.GRPCConfig
		expectNil bool
	}{
		{
			name: "successful server creation",
			cfg: &config.GRPCConfig{
				Host: "localhost",
				Port: 50051,
			},
			expectNil: false,
		},
		{
			name:      "creation with nil config",
			cfg:       nil,
			expectNil: false,
		},
	}

	for _, tcc := range testCases {
		ttcc := tcc
		t.Run(ttcc.name, func(t *testing.T) {
			t.Parallel()

			server := grpcAdapter.New(ttcc.cfg)

			if ttcc.expectNil {
				assert.Nil(t, server)
			} else {
				assert.NotNil(t, server)
			}
		})
	}
}

func TestStart(t *testing.T) {
	t.Parallel()

	testLogger, err := logger.NewLogger(logger.Development, "debug")
	require.NoError(t, err)
	ctx := logger.NewContext(context.Background(), testLogger)

	testCases := []struct {
		name        string
		cfg         *config.GRPCConfig
		expectError bool
	}{
		{
			name: "successful server start",
			cfg: &config.GRPCConfig{
				Host: "localhost",
				Port: 0,
			},
			expectError: false,
		},
		{
			name: "address already in use",
			cfg: func() *config.GRPCConfig {
				listener, err := net.Listen("tcp", "localhost:0")
				require.NoError(t, err)

				port := listener.Addr().(*net.TCPAddr).Port

				t.Cleanup(func() {
					if err := listener.Close(); err != nil {
						t.Logf(LogFailedToCloseListener+": %v", err)
					}
				})

				return &config.GRPCConfig{
					Host: "localhost",
					Port: port,
				}
			}(),
			expectError: true,
		},
		{
			name: "invalid host",
			cfg: &config.GRPCConfig{
				Host: "invalid-hostname-that-cannot-resolve",
				Port: 50051,
			},
			expectError: true,
		},
		{
			name: "invalid port",
			cfg: &config.GRPCConfig{
				Host: "localhost",
				Port: -1,
			},
			expectError: true,
		},
		{
			name: "retry listener closes",
			cfg: func() *config.GRPCConfig {
				listener, err := net.Listen("tcp", "localhost:0")
				require.NoError(t, err)

				port := listener.Addr().(*net.TCPAddr).Port

				t.Cleanup(func() {
					err := listener.Close()
					if err != nil {
						t.Logf(LogFailedToCloseListener+": %v", err)
					}
				})

				return &config.GRPCConfig{
					Host: "localhost",
					Port: port,
				}
			}(),
			expectError: true,
		},
	}

	for _, tcc := range testCases {
		ttcc := tcc
		t.Run(ttcc.name, func(t *testing.T) {
			t.Parallel()

			server := grpcAdapter.New(ttcc.cfg)
			require.NotNil(t, server)

			err := server.Start(ctx)

			if ttcc.expectError {
				require.Error(t, err)
			} else {
				require.NoError(t, err)

				time.Sleep(100 * time.Millisecond)

				server.Stop(ctx)
			}
		})
	}
}

const (
	LogFailedToCloseListener     = "failed to close listener"
	LogFailedToCloseConnection   = "failed to close connection"
	LogServerListeningBeforeStop = "server should be listening before stopping"
	LogConnectionFailAfterStop   = "connection should fail after server is stopped"
)

func TestStop(t *testing.T) {
	t.Parallel()

	testLogger, err := logger.NewLogger(logger.Development, "debug")
	require.NoError(t, err)
	ctx := logger.NewContext(context.Background(), testLogger)

	testCases := []struct {
		name string
	}{
		{
			name: "graceful shutdown",
		},
		{
			name: "stop server without starting",
		},
	}

	for _, tcc := range testCases {
		ttcc := tcc
		t.Run(ttcc.name, func(t *testing.T) {
			t.Parallel()

			switch ttcc.name {
			case "graceful shutdown":
				listener, err := net.Listen("tcp", "localhost:0")
				require.NoError(t, err)

				port := listener.Addr().(*net.TCPAddr).Port
				address := fmt.Sprintf("localhost:%d", port)

				if err := listener.Close(); err != nil {
					t.Logf(LogFailedToCloseListener+": %v", err)
				}

				cfg := &config.GRPCConfig{
					Host: "localhost",
					Port: port,
				}
				server := grpcAdapter.New(cfg)
				require.NotNil(t, server)

				err = server.Start(ctx)
				require.NoError(t, err)

				time.Sleep(100 * time.Millisecond)

				conn, err := net.DialTimeout("tcp", address, 500*time.Millisecond)
				require.NoError(t, err, LogServerListeningBeforeStop)

				if err := conn.Close(); err != nil {
					t.Logf(LogFailedToCloseConnection+": %v", err)
				}

				server.Stop(ctx)

				_, err = net.DialTimeout("tcp", address, 500*time.Millisecond)
				require.Error(t, err, LogConnectionFailAfterStop)

			case "stop server without starting":
				cfg := &config.GRPCConfig{
					Host: "localhost",
					Port: 0,
				}
				server := grpcAdapter.New(cfg)
				require.NotNil(t, server)

				server.Stop(ctx)
			}
		})
	}
}

const (
	registrationFunctionCalledMsg   = "registration function should be called"
	serverPassedToRegistrationFnMsg = "server should be passed to registration function"
)

func TestRegisterService(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name string
	}{
		{
			name: "successfully register service",
		},
	}

	for _, tcc := range testCases {
		ttcc := tcc
		t.Run(ttcc.name, func(t *testing.T) {
			t.Parallel()

			cfg := &config.GRPCConfig{
				Host: "localhost",
				Port: 50051,
			}
			server := grpcAdapter.New(cfg)
			assert.NotNil(t, server)

			var called int32
			var passedServer *grpc.Server
			mockRegisterFn := func(srv *grpc.Server) {
				atomic.StoreInt32(&called, 1)
				passedServer = srv
			}

			server.RegisterService(mockRegisterFn)

			assert.Equal(t, int32(1), atomic.LoadInt32(&called), registrationFunctionCalledMsg)
			assert.NotNil(t, passedServer, serverPassedToRegistrationFnMsg)
		})
	}
}

var (
	ErrInvalidCredentials = errors.New("invalid credentials")
	ErrUserNotFound       = errors.New("user not found")
	ErrDatabaseConnection = errors.New("database connection error")
)

func TestLogin(t *testing.T) {
	err := logger.InitGlobalLoggerWithLevel(logger.Development, "debug")
	require.NoError(t, err)

	testCases := []struct {
		name           string
		req            *authv1.LoginRequest
		setupMock      func(mock *MockAuthUseCase)
		expectedError  error
		validateResult func(t *testing.T, response *authv1.LoginResponse)
	}{
		{
			name: "successful login",
			req: &authv1.LoginRequest{
				Email:    "test@example.com",
				Password: "password123",
			},
			setupMock: func(mockAuth *MockAuthUseCase) {
				expiresAt := time.Now().Add(24 * time.Hour)
				tokenPair := &services.TokenPair{
					UserID:       "user-123",
					Username:     "testuser",
					AccessToken:  "access-token",
					RefreshToken: "refresh-token",
					ExpiresAt:    expiresAt,
				}
				mockAuth.On("Login", mock.Anything, "test@example.com", "password123").Return(tokenPair, nil)
			},
			expectedError: nil,
			validateResult: func(t *testing.T, response *authv1.LoginResponse) {
				t.Helper()
				assert.NotNil(t, response)
				assert.Equal(t, "user-123", response.UserId)
				assert.Equal(t, "testuser", response.Username)
				assert.Equal(t, "access-token", response.AccessToken)
				assert.Equal(t, "refresh-token", response.RefreshToken)
				assert.NotNil(t, response.ExpiresAt)

				assert.True(t, response.ExpiresAt.AsTime().After(time.Now()))
			},
		},
		{
			name: "missing email",
			req: &authv1.LoginRequest{
				Email:    "",
				Password: "password123",
			},
			setupMock: func(_ *MockAuthUseCase) {
			},
			expectedError: grpcAdapter.ErrInvalidRequest,
			validateResult: func(t *testing.T, response *authv1.LoginResponse) {
				t.Helper()
				assert.Nil(t, response)
			},
		},
		{
			name: "missing password",
			req: &authv1.LoginRequest{
				Email:    "test@example.com",
				Password: "",
			},
			setupMock: func(_ *MockAuthUseCase) {
			},
			expectedError: grpcAdapter.ErrInvalidRequest,
			validateResult: func(t *testing.T, response *authv1.LoginResponse) {
				t.Helper()
				assert.Nil(t, response)
			},
		},
		{
			name: "invalid credentials",
			req: &authv1.LoginRequest{
				Email:    "test@example.com",
				Password: "wrongpassword",
			},
			setupMock: func(mockAuth *MockAuthUseCase) {
				mockAuth.On("Login", mock.Anything, "test@example.com", "wrongpassword").
					Return(nil, ErrInvalidCredentials)
			},
			expectedError: grpcAdapter.ErrInvalidCredentials,
			validateResult: func(t *testing.T, response *authv1.LoginResponse) {
				t.Helper()
				assert.Nil(t, response)
			},
		},
		{
			name: "user not found",
			req: &authv1.LoginRequest{
				Email:    "nonexistent@example.com",
				Password: "password123",
			},
			setupMock: func(mockAuth *MockAuthUseCase) {
				mockAuth.On("Login", mock.Anything, "nonexistent@example.com", "password123").
					Return(nil, ErrUserNotFound)
			},
			expectedError: grpcAdapter.ErrInvalidCredentials,
			validateResult: func(t *testing.T, response *authv1.LoginResponse) {
				t.Helper()
				assert.Nil(t, response)
			},
		},
		{
			name: "internal service error",
			req: &authv1.LoginRequest{
				Email:    "test@example.com",
				Password: "password123",
			},
			setupMock: func(mockAuth *MockAuthUseCase) {
				mockAuth.On("Login", mock.Anything, "test@example.com", "password123").
					Return(nil, ErrDatabaseConnection)
			},
			expectedError: grpcAdapter.ErrInvalidCredentials,
			validateResult: func(t *testing.T, response *authv1.LoginResponse) {
				t.Helper()
				assert.Nil(t, response)
			},
		},
		{
			name: "all fields populated correctly",
			req: &authv1.LoginRequest{
				Email:    "complete@example.com",
				Password: "fullpassword",
			},
			setupMock: func(mockAuth *MockAuthUseCase) {
				expiresAt := time.Now().Add(24 * time.Hour)
				tokenPair := &services.TokenPair{
					UserID:       "user-complete",
					Username:     "completeuser",
					AccessToken:  "complete-access-token",
					RefreshToken: "complete-refresh-token",
					ExpiresAt:    expiresAt,
				}
				mockAuth.On("Login", mock.Anything, "complete@example.com", "fullpassword").Return(tokenPair, nil)
			},
			expectedError: nil,
			validateResult: func(t *testing.T, response *authv1.LoginResponse) {
				t.Helper()
				assert.NotNil(t, response)

				assert.Equal(t, "user-complete", response.UserId)
				assert.Equal(t, "completeuser", response.Username)
				assert.Equal(t, "complete-access-token", response.AccessToken)
				assert.Equal(t, "complete-refresh-token", response.RefreshToken)

				assert.NotNil(t, response.ExpiresAt)
				assert.IsType(t, &timestamppb.Timestamp{}, response.ExpiresAt)
				assert.True(t, response.ExpiresAt.AsTime().After(time.Now()))
			},
		},
	}

	for _, tcc := range testCases {
		t.Run(tcc.name, func(t *testing.T) {
			mockAuthUseCase := new(MockAuthUseCase)
			tcc.setupMock(mockAuthUseCase)

			handler := grpcAdapter.NewAuthHandler(mockAuthUseCase)

			ctx := context.Background()
			ctx = logger.NewRequestIDContext(ctx, "test-request-id")

			response, err := handler.Login(ctx, tcc.req)

			if tcc.expectedError != nil {
				require.Error(t, err)
				require.ErrorIs(t, err, tcc.expectedError)
			} else {
				require.NoError(t, err)
			}

			tcc.validateResult(t, response)
			mockAuthUseCase.AssertExpectations(t)
		})
	}
}

var (
	ErrInvalidToken = errors.New(grpcAdapter.ErrInvalidTokenMsg)
)

func TestLogout(t *testing.T) {
	err := logger.InitGlobalLoggerWithLevel(logger.Development, "debug")
	require.NoError(t, err)

	testCases := []struct {
		name          string
		req           *authv1.LogoutRequest
		setupMock     func(mock *MockAuthUseCase)
		expectedError error
	}{
		{
			name: "successful logout",
			req: &authv1.LogoutRequest{
				RefreshToken: "valid-refresh-token",
			},
			setupMock: func(mockAuth *MockAuthUseCase) {
				mockAuth.On("Logout", mock.Anything, "valid-refresh-token").Return(nil)
			},
			expectedError: nil,
		},
		{
			name: "missing refresh token",
			req: &authv1.LogoutRequest{
				RefreshToken: "",
			},
			setupMock: func(_ *MockAuthUseCase) {
			},
			expectedError: grpcAdapter.ErrInvalidRequest,
		},
		{
			name: "invalid refresh token",
			req: &authv1.LogoutRequest{
				RefreshToken: "invalid-token",
			},
			setupMock: func(mockAuth *MockAuthUseCase) {
				mockAuth.On("Logout", mock.Anything, "invalid-token").
					Return(ErrInvalidToken)
			},
			expectedError: grpcAdapter.ErrInvalidToken,
		},
		{
			name: "expired refresh token",
			req: &authv1.LogoutRequest{
				RefreshToken: "expired-token",
			},
			setupMock: func(mockAuth *MockAuthUseCase) {
				mockAuth.On("Logout", mock.Anything, "expired-token").
					Return(ErrInvalidToken)
			},
			expectedError: grpcAdapter.ErrInvalidToken,
		},
		{
			name: "internal service error",
			req: &authv1.LogoutRequest{
				RefreshToken: "valid-token",
			},
			setupMock: func(mockAuth *MockAuthUseCase) {
				mockAuth.On("Logout", mock.Anything, "valid-token").
					Return(ErrDatabaseConnection)
			},
			expectedError: grpcAdapter.ErrAuthServiceInternal,
		},
	}

	for _, tcc := range testCases {
		t.Run(tcc.name, func(t *testing.T) {
			mockAuthUseCase := new(MockAuthUseCase)
			tcc.setupMock(mockAuthUseCase)

			handler := grpcAdapter.NewAuthHandler(mockAuthUseCase)

			ctx := context.Background()
			ctx = logger.NewRequestIDContext(ctx, "test-request-id")

			response, err := handler.Logout(ctx, tcc.req)

			if tcc.expectedError != nil {
				require.Error(t, err)
				require.ErrorIs(t, err, tcc.expectedError)
				assert.Nil(t, response)
			} else {
				require.NoError(t, err)
				assert.NotNil(t, response)
				assert.IsType(t, &emptypb.Empty{}, response)
			}

			mockAuthUseCase.AssertExpectations(t)
		})
	}
}

const (
	testCreateHandlerWithUseCaseMsg = "should create auth handler with provided auth use case"
	testHandlerShouldNotBeNilMsg    = "handler should not be nil"
	testImplementInterfaceMsg       = "handler should implement required interface"
)

type MockAuthUseCase struct {
	mock.Mock
}

//nolint:wrapcheck
func (m *MockAuthUseCase) Register(ctx context.Context, email, username, password string) (*services.TokenPair, error) {
	args := m.Called(ctx, email, username, password)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	if args.Error(1) == nil {
		return args.Get(0).(*services.TokenPair), nil
	}
	return args.Get(0).(*services.TokenPair), args.Error(1)
}

//nolint:wrapcheck
func (m *MockAuthUseCase) Login(ctx context.Context, email, password string) (*services.TokenPair, error) {
	args := m.Called(ctx, email, password)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	if args.Error(1) == nil {
		return args.Get(0).(*services.TokenPair), nil
	}
	return args.Get(0).(*services.TokenPair), args.Error(1)
}

//nolint:wrapcheck
func (m *MockAuthUseCase) RefreshTokens(ctx context.Context, refreshToken string) (*services.TokenPair, error) {
	args := m.Called(ctx, refreshToken)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	if args.Error(1) == nil {
		return args.Get(0).(*services.TokenPair), nil
	}
	return args.Get(0).(*services.TokenPair), args.Error(1)
}

//nolint:wrapcheck
func (m *MockAuthUseCase) Logout(ctx context.Context, refreshToken string) error {
	args := m.Called(ctx, refreshToken)
	return args.Error(0)
}

func TestNewAuthHandler(t *testing.T) {
	t.Run(testCreateHandlerWithUseCaseMsg, func(t *testing.T) {
		mockAuthUseCase := new(MockAuthUseCase)
		handler := grpcAdapter.NewAuthHandler(mockAuthUseCase)

		assert.NotNil(t, handler, testHandlerShouldNotBeNilMsg)
	})

	t.Run(testImplementInterfaceMsg, func(_ *testing.T) {
		mockAuthUseCase := new(MockAuthUseCase)

		handler := grpcAdapter.NewAuthHandler(mockAuthUseCase)

		var _ any = handler
	})
}

var (
	ErrTokenExpired = errors.New("token has expired")
)

func TestRefreshTokens(t *testing.T) {
	err := logger.InitGlobalLoggerWithLevel(logger.Development, "debug")
	require.NoError(t, err)

	testCases := []struct {
		name           string
		req            *authv1.RefreshTokensRequest
		setupMock      func(mock *MockAuthUseCase)
		expectedError  error
		validateResult func(t *testing.T, response *authv1.RefreshTokensResponse)
	}{
		{
			name: "successful token refresh",
			req: &authv1.RefreshTokensRequest{
				RefreshToken: "valid-refresh-token",
			},
			setupMock: func(mockAuth *MockAuthUseCase) {
				expiresAt := time.Now().Add(24 * time.Hour)
				tokenPair := &services.TokenPair{
					UserID:       "user-123",
					Username:     "testuser",
					AccessToken:  "new-access-token",
					RefreshToken: "new-refresh-token",
					ExpiresAt:    expiresAt,
				}
				mockAuth.On("RefreshTokens", mock.Anything, "valid-refresh-token").Return(tokenPair, nil)
			},
			expectedError: nil,
			validateResult: func(t *testing.T, response *authv1.RefreshTokensResponse) {
				t.Helper()
				assert.NotNil(t, response)
				assert.Equal(t, "new-access-token", response.AccessToken)
				assert.Equal(t, "new-refresh-token", response.RefreshToken)
				assert.NotNil(t, response.ExpiresAt)
				assert.True(t, response.ExpiresAt.AsTime().After(time.Now()))
			},
		},
		{
			name: "missing refresh token",
			req: &authv1.RefreshTokensRequest{
				RefreshToken: "",
			},
			setupMock: func(_ *MockAuthUseCase) {
			},
			expectedError: grpcAdapter.ErrInvalidRequest,
			validateResult: func(t *testing.T, response *authv1.RefreshTokensResponse) {
				t.Helper()
				assert.Nil(t, response)
			},
		},
		{
			name: "invalid refresh token",
			req: &authv1.RefreshTokensRequest{
				RefreshToken: "invalid-token",
			},
			setupMock: func(mockAuth *MockAuthUseCase) {
				mockAuth.On("RefreshTokens", mock.Anything, "invalid-token").
					Return(nil, ErrInvalidToken)
			},
			expectedError: grpcAdapter.ErrInvalidToken,
			validateResult: func(t *testing.T, response *authv1.RefreshTokensResponse) {
				t.Helper()
				assert.Nil(t, response)
			},
		},
		{
			name: "expired refresh token",
			req: &authv1.RefreshTokensRequest{
				RefreshToken: "expired-token",
			},
			setupMock: func(mockAuth *MockAuthUseCase) {
				mockAuth.On("RefreshTokens", mock.Anything, "expired-token").
					Return(nil, ErrTokenExpired)
			},
			expectedError: grpcAdapter.ErrInvalidToken,
			validateResult: func(t *testing.T, response *authv1.RefreshTokensResponse) {
				t.Helper()
				assert.Nil(t, response)
			},
		},
		{
			name: "internal service error",
			req: &authv1.RefreshTokensRequest{
				RefreshToken: "valid-token",
			},
			setupMock: func(mockAuth *MockAuthUseCase) {
				mockAuth.On("RefreshTokens", mock.Anything, "valid-token").
					Return(nil, ErrDatabaseConnection)
			},
			expectedError: grpcAdapter.ErrInvalidToken,
			validateResult: func(t *testing.T, response *authv1.RefreshTokensResponse) {
				t.Helper()
				assert.Nil(t, response)
			},
		},
		{
			name: "full verification of token fields",
			req: &authv1.RefreshTokensRequest{
				RefreshToken: "full-verification-token",
			},
			setupMock: func(mockAuth *MockAuthUseCase) {
				expiresAt := time.Now().Add(24 * time.Hour)
				tokenPair := &services.TokenPair{
					UserID:       "user-456",
					Username:     "fulluser",
					AccessToken:  "complete-access-token",
					RefreshToken: "complete-refresh-token",
					ExpiresAt:    expiresAt,
				}
				mockAuth.On("RefreshTokens", mock.Anything, "full-verification-token").Return(tokenPair, nil)
			},
			expectedError: nil,
			validateResult: func(t *testing.T, response *authv1.RefreshTokensResponse) {
				t.Helper()
				assert.NotNil(t, response)

				assert.Equal(t, "complete-access-token", response.AccessToken)
				assert.Equal(t, "complete-refresh-token", response.RefreshToken)

				assert.NotNil(t, response.ExpiresAt)
				assert.IsType(t, &timestamppb.Timestamp{}, response.ExpiresAt)
				assert.True(t, response.ExpiresAt.AsTime().After(time.Now()))
			},
		},
	}

	for _, tcc := range testCases {
		t.Run(tcc.name, func(t *testing.T) {
			mockAuthUseCase := new(MockAuthUseCase)
			tcc.setupMock(mockAuthUseCase)

			handler := grpcAdapter.NewAuthHandler(mockAuthUseCase)

			ctx := context.Background()
			ctx = logger.NewRequestIDContext(ctx, "test-request-id")

			response, err := handler.RefreshTokens(ctx, tcc.req)

			if tcc.expectedError != nil {
				require.Error(t, err)
				require.ErrorIs(t, err, tcc.expectedError)
			} else {
				require.NoError(t, err)
			}

			tcc.validateResult(t, response)
			mockAuthUseCase.AssertExpectations(t)
		})
	}
}

const (
	RegServiceShouldNPanicWithRealServerMsg = "RegisterService should not panic with a real gRPC server"
	AuthServiceRegisteredMsg                = "AuthService should be registered with the server"
)

type MockGRPCServer struct {
	mock.Mock
}

func (m *MockGRPCServer) RegisterService(desc *grpc.ServiceDesc, impl interface{}) {
	m.Called(desc, impl)
}

var (
	ErrUserAlreadyExists = errors.New(grpcAdapter.ErrUserAlreadyExistsMsg)
)

func TestRegister(t *testing.T) {
	err := logger.InitGlobalLoggerWithLevel(logger.Development, "debug")
	require.NoError(t, err)

	testCases := []struct {
		name           string
		req            *authv1.RegisterRequest
		setupMock      func(mock *MockAuthUseCase)
		expectedError  error
		validateResult func(t *testing.T, response *authv1.RegisterResponse)
	}{
		{
			name: "successful registration",
			req: &authv1.RegisterRequest{
				Email:    "test@example.com",
				Username: "testuser",
				Password: "password123",
			},
			setupMock: func(mockAuth *MockAuthUseCase) {
				expiresAt := time.Now().Add(24 * time.Hour)
				tokenPair := &services.TokenPair{
					UserID:       "user-123",
					Username:     "testuser",
					AccessToken:  "access-token",
					RefreshToken: "refresh-token",
					ExpiresAt:    expiresAt,
				}
				mockAuth.On("Register", mock.Anything, "test@example.com", "testuser", "password123").Return(tokenPair, nil)
			},
			expectedError: nil,
			validateResult: func(t *testing.T, response *authv1.RegisterResponse) {
				t.Helper()
				assert.NotNil(t, response)
				assert.Equal(t, "user-123", response.UserId)
				assert.Equal(t, "access-token", response.AccessToken)
				assert.Equal(t, "refresh-token", response.RefreshToken)
				assert.NotNil(t, response.ExpiresAt)
			},
		},
		{
			name: "missing email",
			req: &authv1.RegisterRequest{
				Email:    "",
				Username: "testuser",
				Password: "password123",
			},
			setupMock: func(_ *MockAuthUseCase) {
			},
			expectedError: grpcAdapter.ErrInvalidRequest,
			validateResult: func(t *testing.T, response *authv1.RegisterResponse) {
				t.Helper()
				assert.Nil(t, response)
			},
		},
		{
			name: "missing username",
			req: &authv1.RegisterRequest{
				Email:    "test@example.com",
				Username: "",
				Password: "password123",
			},
			setupMock: func(_ *MockAuthUseCase) {
			},
			expectedError: grpcAdapter.ErrInvalidRequest,
			validateResult: func(t *testing.T, response *authv1.RegisterResponse) {
				t.Helper()
				assert.Nil(t, response)
			},
		},
		{
			name: "missing password",
			req: &authv1.RegisterRequest{
				Email:    "test@example.com",
				Username: "testuser",
				Password: "",
			},
			setupMock: func(_ *MockAuthUseCase) {
			},
			expectedError: grpcAdapter.ErrInvalidRequest,
			validateResult: func(t *testing.T, response *authv1.RegisterResponse) {
				t.Helper()
				assert.Nil(t, response)
			},
		},
		{
			name: "user already exists",
			req: &authv1.RegisterRequest{
				Email:    "existing@example.com",
				Username: "existinguser",
				Password: "password123",
			},
			setupMock: func(mockAuth *MockAuthUseCase) {
				mockAuth.On("Register", mock.Anything, "existing@example.com", "existinguser", "password123").
					Return(nil, ErrUserAlreadyExists)
			},
			expectedError: grpcAdapter.ErrUserAlreadyExists,
			validateResult: func(t *testing.T, response *authv1.RegisterResponse) {
				t.Helper()
				assert.Nil(t, response)
			},
		},
		{
			name: "internal service error",
			req: &authv1.RegisterRequest{
				Email:    "test@example.com",
				Username: "testuser",
				Password: "password123",
			},
			setupMock: func(mockAuth *MockAuthUseCase) {
				mockAuth.On("Register", mock.Anything, "test@example.com", "testuser", "password123").
					Return(nil, ErrDatabaseConnection)
			},
			expectedError: grpcAdapter.ErrAuthServiceInternal,
			validateResult: func(t *testing.T, response *authv1.RegisterResponse) {
				t.Helper()
				assert.Nil(t, response)
			},
		},
	}

	for _, tcc := range testCases {
		t.Run(tcc.name, func(t *testing.T) {
			mockAuthUseCase := new(MockAuthUseCase)
			tcc.setupMock(mockAuthUseCase)

			handler := grpcAdapter.NewAuthHandler(mockAuthUseCase)

			ctx := context.Background()
			ctx = logger.NewRequestIDContext(ctx, "test-request-id")

			response, err := handler.Register(ctx, tcc.req)

			if tcc.expectedError != nil {
				require.Error(t, err)
				require.ErrorIs(t, err, tcc.expectedError)
			} else {
				require.NoError(t, err)
			}

			tcc.validateResult(t, response)
			mockAuthUseCase.AssertExpectations(t)
		})
	}
}

const (
	validUserID         = "test-user-id-123"
	userIDRetrievedMsg  = "valid userID should be retrieved from context"
	noUserIDExpectedMsg = "no userID should be retrieved in this case"
)

//nolint:gosec
const (
	validTokenMock   = "valid-token-string-for-testing"
	invalidTokenMock = "invalid-token"
)

func TestGetUserIDFromContext(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name              string
		setupContext      func() context.Context
		setupTokenService func(mockSvc *TokenService)
		setupUserUseCase  func(mockUseCase *UserUseCase)
		expectedUserID    string
		expectedOK        bool
		message           string
	}{
		{
			name: "successful userID extraction",
			setupContext: func() context.Context {
				ctx := context.Background()
				ctx = logger.NewContext(ctx, logger.Log(ctx))
				md := metadata.New(map[string]string{
					"authorization": "Bearer " + validTokenMock,
				})
				return metadata.NewIncomingContext(ctx, md)
			},
			setupTokenService: func(mockSvc *TokenService) {
				mockSvc.On("ValidateAccessToken", mock.Anything, validTokenMock).Return(validUserID, nil)
			},
			setupUserUseCase: func(mockUseCase *UserUseCase) {
				mockUseCase.On("GetUserProfile", mock.Anything, validUserID).Return(&entities.User{
					ID:        validUserID,
					Email:     "test@example.com",
					Username:  "testuser",
					CreatedAt: time.Now(),
				}, nil)
			},
			expectedUserID: validUserID,
			expectedOK:     true,
			message:        userIDRetrievedMsg,
		},
		{
			name: "missing metadata",
			setupContext: func() context.Context {
				ctx := context.Background()
				ctx = logger.NewContext(ctx, logger.Log(ctx))
				return ctx
			},
			setupTokenService: func(_ *TokenService) {
			},
			setupUserUseCase: func(_ *UserUseCase) {
			},
			expectedUserID: "",
			expectedOK:     false,
			message:        noUserIDExpectedMsg,
		},
		{
			name: "missing authorization header",
			setupContext: func() context.Context {
				ctx := context.Background()
				ctx = logger.NewContext(ctx, logger.Log(ctx))
				md := metadata.New(map[string]string{})
				return metadata.NewIncomingContext(ctx, md)
			},
			setupTokenService: func(_ *TokenService) {
			},
			setupUserUseCase: func(_ *UserUseCase) {
			},
			expectedUserID: "",
			expectedOK:     false,
			message:        noUserIDExpectedMsg,
		},
		{
			name: "invalid token format - missing Bearer prefix",
			setupContext: func() context.Context {
				ctx := context.Background()
				ctx = logger.NewContext(ctx, logger.Log(ctx))
				md := metadata.New(map[string]string{
					"authorization": validTokenMock,
				})
				return metadata.NewIncomingContext(ctx, md)
			},
			setupTokenService: func(_ *TokenService) {
			},
			setupUserUseCase: func(_ *UserUseCase) {
			},
			expectedUserID: "",
			expectedOK:     false,
			message:        noUserIDExpectedMsg,
		},
		{
			name: "token validation error",
			setupContext: func() context.Context {
				ctx := context.Background()
				ctx = logger.NewContext(ctx, logger.Log(ctx))
				md := metadata.New(map[string]string{
					"authorization": "Bearer " + invalidTokenMock,
				})
				return metadata.NewIncomingContext(ctx, md)
			},
			setupTokenService: func(mockSvc *TokenService) {
				mockSvc.On("ValidateAccessToken", mock.Anything, invalidTokenMock).Return("", errTokenValidation)
			},
			setupUserUseCase: func(_ *UserUseCase) {
			},
			expectedUserID: "",
			expectedOK:     false,
			message:        noUserIDExpectedMsg,
		},
	}

	for _, tc := range testCases {
		tcc := tc
		t.Run(tcc.name, func(t *testing.T) {
			t.Parallel()

			mockTokenSvc := new(TokenService)
			mockUseCase := new(UserUseCase)

			tcc.setupTokenService(mockTokenSvc)
			tcc.setupUserUseCase(mockUseCase)

			handler := grpcAdapter.NewUserHandler(mockUseCase, mockTokenSvc)

			ctx := tcc.setupContext()

			resp, err := handler.GetUserProfile(ctx, &emptypb.Empty{})

			if tcc.expectedOK {
				require.NoError(t, err)
				assert.NotNil(t, resp)
				assert.Equal(t, validUserID, resp.UserId)
			} else {
				require.Error(t, err)
				assert.Contains(t, err.Error(), grpcAdapter.ErrMissingUserIDMsg,
					"Error should be about missing user ID")
				assert.Nil(t, resp)
			}

			mockTokenSvc.AssertExpectations(t)
			mockUseCase.AssertExpectations(t)
		})
	}
}

const (
	testUserID   = "test-user-id"
	testEmail    = "test@example.com"
	testUsername = "testuser"
	testToken    = "valid-token"
)

var (
	errTokenValidation = errors.New("token validation failed")
	errUnexpected      = errors.New("unexpected error")
)

func TestGetUserProfile(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name           string
		setupMocks     func(mockUseCase *UserUseCase, mockTokenSvc *TokenService)
		setupContext   func() context.Context
		expectedError  error
		validateResult func(t *testing.T, result interface{}, err error)
	}{
		{
			name: "successful get user profile",
			setupMocks: func(mockUseCase *UserUseCase, mockTokenSvc *TokenService) {
				createdAt := time.Now()
				mockTokenSvc.On("ValidateAccessToken", mock.Anything, testToken).Return(testUserID, nil)
				mockUseCase.On("GetUserProfile", mock.Anything, testUserID).Return(&entities.User{
					ID:        testUserID,
					Email:     testEmail,
					Username:  testUsername,
					CreatedAt: createdAt,
				}, nil)
			},
			setupContext: func() context.Context {
				ctx := context.Background()
				ctx = logger.NewContext(ctx, logger.Log(ctx))
				md := metadata.New(map[string]string{
					"authorization": "Bearer " + testToken,
				})
				return metadata.NewIncomingContext(ctx, md)
			},
			expectedError: nil,
			validateResult: func(t *testing.T, result interface{}, err error) {
				t.Helper()
				require.NoError(t, err)
				assert.NotNil(t, result)
				response := result.(*authv1.UserProfileResponse)
				assert.Equal(t, testUserID, response.UserId)
				assert.Equal(t, testEmail, response.Email)
				assert.Equal(t, testUsername, response.Username)
				assert.NotNil(t, response.CreatedAt)
			},
		},
		{
			name: "missing metadata",
			setupMocks: func(_ *UserUseCase, _ *TokenService) {
			},
			setupContext: func() context.Context {
				ctx := context.Background()
				ctx = logger.NewContext(ctx, logger.Log(ctx))
				return ctx
			},
			expectedError: grpcAdapter.ErrMissingUserID,
			validateResult: func(t *testing.T, result interface{}, err error) {
				t.Helper()
				require.Error(t, err)
				assert.Nil(t, result)
				assert.ErrorIs(t, err, grpcAdapter.ErrMissingUserID)
			},
		},
		{
			name: "missing authorization header",
			setupMocks: func(_ *UserUseCase, _ *TokenService) {
			},
			setupContext: func() context.Context {
				ctx := context.Background()
				ctx = logger.NewContext(ctx, logger.Log(ctx))
				md := metadata.New(map[string]string{})
				return metadata.NewIncomingContext(ctx, md)
			},
			expectedError: grpcAdapter.ErrMissingUserID,
			validateResult: func(t *testing.T, result interface{}, err error) {
				t.Helper()
				require.Error(t, err)
				assert.Nil(t, result)
				assert.ErrorIs(t, err, grpcAdapter.ErrMissingUserID)
			},
		},
		{
			name: "invalid token format",
			setupMocks: func(_ *UserUseCase, _ *TokenService) {
			},
			setupContext: func() context.Context {
				ctx := context.Background()
				ctx = logger.NewContext(ctx, logger.Log(ctx))
				md := metadata.New(map[string]string{
					"authorization": "InvalidFormat",
				})
				return metadata.NewIncomingContext(ctx, md)
			},
			expectedError: grpcAdapter.ErrMissingUserID,
			validateResult: func(t *testing.T, result interface{}, err error) {
				t.Helper()
				require.Error(t, err)
				assert.Nil(t, result)
				assert.ErrorIs(t, err, grpcAdapter.ErrMissingUserID)
			},
		},
		{
			name: "token validation fails",
			setupMocks: func(_ *UserUseCase, mockTokenSvc *TokenService) {
				mockTokenSvc.On("ValidateAccessToken", mock.Anything, testToken).Return("", errTokenValidation)
			},
			setupContext: func() context.Context {
				ctx := context.Background()
				ctx = logger.NewContext(ctx, logger.Log(ctx))
				md := metadata.New(map[string]string{
					"authorization": "Bearer " + testToken,
				})
				return metadata.NewIncomingContext(ctx, md)
			},
			expectedError: grpcAdapter.ErrMissingUserID,
			validateResult: func(t *testing.T, result interface{}, err error) {
				t.Helper()
				require.Error(t, err)
				assert.Nil(t, result)
				assert.ErrorIs(t, err, grpcAdapter.ErrMissingUserID)
			},
		},
		{
			name: "user not found",
			setupMocks: func(mockUseCase *UserUseCase, mockTokenSvc *TokenService) {
				mockTokenSvc.On("ValidateAccessToken", mock.Anything, testToken).Return(testUserID, nil)
				mockUseCase.On("GetUserProfile", mock.Anything, testUserID).Return(nil, fmt.Errorf("%w", grpcAdapter.ErrUserNotFound))
			},
			setupContext: func() context.Context {
				ctx := context.Background()
				ctx = logger.NewContext(ctx, logger.Log(ctx))
				md := metadata.New(map[string]string{
					"authorization": "Bearer " + testToken,
				})
				return metadata.NewIncomingContext(ctx, md)
			},
			expectedError: grpcAdapter.ErrUserNotFound,
			validateResult: func(t *testing.T, result interface{}, err error) {
				t.Helper()
				require.Error(t, err)
				assert.Nil(t, result)
				assert.ErrorIs(t, err, grpcAdapter.ErrUserNotFound)
			},
		},
		{
			name: "internal service error",
			setupMocks: func(mockUseCase *UserUseCase, mockTokenSvc *TokenService) {
				mockTokenSvc.On("ValidateAccessToken", mock.Anything, testToken).Return(testUserID, nil)
				mockUseCase.On("GetUserProfile", mock.Anything, testUserID).Return(nil, errUnexpected)
			},
			setupContext: func() context.Context {
				ctx := context.Background()
				ctx = logger.NewContext(ctx, logger.Log(ctx))
				md := metadata.New(map[string]string{
					"authorization": "Bearer " + testToken,
				})
				return metadata.NewIncomingContext(ctx, md)
			},
			expectedError: grpcAdapter.ErrInternalService,
			validateResult: func(t *testing.T, result interface{}, err error) {
				t.Helper()
				require.Error(t, err)
				assert.Nil(t, result)
				assert.ErrorIs(t, err, grpcAdapter.ErrInternalService)
			},
		},
	}

	for _, tc := range testCases {
		tcc := tc
		t.Run(tcc.name, func(t *testing.T) {
			t.Parallel()

			mockUseCase := new(UserUseCase)
			mockTokenSvc := new(TokenService)

			tcc.setupMocks(mockUseCase, mockTokenSvc)

			handler := grpcAdapter.NewUserHandler(mockUseCase, mockTokenSvc)
			ctx := tcc.setupContext()

			result, err := handler.GetUserProfile(ctx, &emptypb.Empty{})

			tcc.validateResult(t, result, err)
			mockUseCase.AssertExpectations(t)
			mockTokenSvc.AssertExpectations(t)
		})
	}
}

const (
	handlerNotNilAssertion          = "handler should not be nil"
	handlerShouldImplementAssertion = "handler should implement UserServiceServer interface"
	getUserProfileAssertion         = "GetUserProfile should return error when userID is missing"
)

func TestNewUserHandler(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name string
	}{
		{
			name: "successfully create user handler",
		},
	}

	for _, tc := range testCases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			mockUseCase := new(UserUseCase)
			mockTokenSvc := new(TokenService)

			handler := grpcAdapter.NewUserHandler(mockUseCase, mockTokenSvc)

			assert.NotNil(t, handler, handlerNotNilAssertion)

			_, ok := interface{}(handler).(authv1.UserServiceServer)
			assert.True(t, ok, handlerShouldImplementAssertion)

			empty := &emptypb.Empty{}
			ctx := context.Background()

			_, err := handler.GetUserProfile(ctx, empty)
			assert.Error(t, err, getUserProfileAssertion)
		})
	}
}

const (
	userServiceRegisteredMsg = "user service should be registered with gRPC server"
	regService               = "RegisterService"
)

type mockGrpcServer struct {
	mock.Mock
}
type TokenService struct {
	mock.Mock
}
type UserUseCase struct {
	mock.Mock
}

func (m *UserUseCase) GetUserProfile(ctx context.Context, userID string) (*entities.User, error) {
	args := m.Called(ctx, userID)

	var user *entities.User
	if args.Get(0) != nil {
		user = args.Get(0).(*entities.User)
	}

	if err := args.Error(1); err != nil {
		return user, fmt.Errorf("mock GetUserProfile error: %w", err)
	}
	return user, nil
}

func (m *TokenService) GenerateAccessToken(ctx context.Context, userID, username string) (string, time.Time, error) {
	args := m.Called(ctx, userID, username)
	return args.String(0), args.Get(1).(time.Time), args.Error(2)
}

func (m *TokenService) GenerateRefreshToken(ctx context.Context, userID string) (string, time.Time, error) {
	args := m.Called(ctx, userID)
	return args.String(0), args.Get(1).(time.Time), args.Error(2)
}

func (m *TokenService) ValidateAccessToken(ctx context.Context, token string) (string, error) {
	args := m.Called(ctx, token)
	return args.String(0), args.Error(1)
}

func (m *mockGrpcServer) RegisterService(desc *grpc.ServiceDesc, impl interface{}) {
	m.Called(desc, impl)
}

func TestUserHandlerRegisterService(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name string
	}{
		{
			name: "successfully register user service",
		},
	}

	for _, tc := range testCases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			mockUseCase := new(UserUseCase)
			mockTokenSvc := new(TokenService)
			mockServer := new(mockGrpcServer)

			mockServer.On(
				regService,
				&authv1.UserService_ServiceDesc,
				mock.AnythingOfType("*grpc.UserHandler"),
			).Return()

			handler := grpcAdapter.NewUserHandler(mockUseCase, mockTokenSvc)
			handler.RegisterService(mockServer)

			mockServer.AssertCalled(t, regService, &authv1.UserService_ServiceDesc, handler)

			assert.True(t, mockServer.AssertNumberOfCalls(t, regService, 1), userServiceRegisteredMsg)
		})
	}
}
