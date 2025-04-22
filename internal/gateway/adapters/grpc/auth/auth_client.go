// Package auth предоставляет реализацию клиента для сервиса авторизации
package auth

import (
	"context"
	"errors"
	"fmt"

	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/grpc/connectivity"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/protobuf/types/known/emptypb"

	"gogetnote/internal/gateway/config"
	grpcPort "gogetnote/internal/gateway/ports/grpc"
	authv1 "gogetnote/pkg/api/auth/v1"
	"gogetnote/pkg/logger"
)

// Константы для логирования.
const (
	LogMethodRegister       = "Register"
	LogMethodLogin          = "Login"
	LogMethodRefreshTokens  = "RefreshTokens"
	LogMethodLogout         = "Logout"
	LogMethodGetUserProfile = "GetUserProfile"

	ErrorFailedToRegister      = "failed to register user"
	ErrorFailedToLogin         = "failed to login"
	ErrorFailedToRefreshTokens = "failed to update tokens"
	ErrorFailedToLogout        = "failed to logout"
	ErrorFailedToGetProfile    = "failed to get user profile"
)

// ErrAuthServiceConnectionTimeout представляет ошибку таймаута соединения с сервисом авторизации.
var ErrAuthServiceConnectionTimeout = errors.New("connection timeout: failed to connect to auth service")

// Client реализует интерфейс AuthServiceClient.
type Client struct {
	authClient authv1.AuthServiceClient
	userClient authv1.UserServiceClient
	conn       *grpc.ClientConn
}

// NewAuthClient создает новый экземпляр клиента авторизации.
func NewAuthClient(cfg *config.GRPCClientConfig) (grpcPort.AuthServiceClient, error) {
	conn, err := grpc.NewClient(
		cfg.AuthService.GetAddress(),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to auth service: %w", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), cfg.AuthService.ConnectTimeout)
	defer cancel()

	conn.Connect()

	for {
		state := conn.GetState()
		if state == connectivity.Ready {
			break
		}
		if !conn.WaitForStateChange(ctx, state) {
			closeErr := conn.Close()
			if closeErr != nil {
				return nil, fmt.Errorf("failed to close connection: %w", closeErr)
			}
			return nil, ErrAuthServiceConnectionTimeout
		}
	}

	return &Client{
		authClient: authv1.NewAuthServiceClient(conn),
		userClient: authv1.NewUserServiceClient(conn),
		conn:       conn,
	}, nil
}

// Register регистрирует нового пользователя.
func (c *Client) Register(ctx context.Context, email, username, password string) (*authv1.RegisterResponse, error) {
	log := logger.Log(ctx).With(zap.String("method", LogMethodRegister))

	req := &authv1.RegisterRequest{
		Email:    email,
		Username: username,
		Password: password,
	}

	resp, err := c.authClient.Register(ctx, req)
	if err != nil {
		log.Error(ctx, ErrorFailedToRegister, zap.Error(err))
		return nil, fmt.Errorf("%s: %w", ErrorFailedToRegister, err)
	}

	return resp, nil
}

// Login выполняет вход пользователя в систему.
func (c *Client) Login(ctx context.Context, email, password string) (*authv1.LoginResponse, error) {
	log := logger.Log(ctx).With(zap.String("method", LogMethodLogin))

	req := &authv1.LoginRequest{
		Email:    email,
		Password: password,
	}

	resp, err := c.authClient.Login(ctx, req)
	if err != nil {
		log.Error(ctx, ErrorFailedToLogin, zap.Error(err))
		return nil, fmt.Errorf("%s: %w", ErrorFailedToLogin, err)
	}

	return resp, nil
}

// RefreshTokens обновляет токены доступа.
func (c *Client) RefreshTokens(ctx context.Context, refreshToken string) (*authv1.RefreshTokensResponse, error) {
	log := logger.Log(ctx).With(zap.String("method", LogMethodRefreshTokens))

	req := &authv1.RefreshTokensRequest{
		RefreshToken: refreshToken,
	}

	resp, err := c.authClient.RefreshTokens(ctx, req)
	if err != nil {
		log.Error(ctx, ErrorFailedToRefreshTokens, zap.Error(err))
		return nil, fmt.Errorf("%s: %w", ErrorFailedToRefreshTokens, err)
	}

	return resp, nil
}

// Logout выполняет выход пользователя из системы.
func (c *Client) Logout(ctx context.Context, refreshToken string) error {
	log := logger.Log(ctx).With(zap.String("method", LogMethodLogout))

	req := &authv1.LogoutRequest{
		RefreshToken: refreshToken,
	}

	_, err := c.authClient.Logout(ctx, req)
	if err != nil {
		log.Error(ctx, ErrorFailedToLogout, zap.Error(err))
		return fmt.Errorf("%s: %w", ErrorFailedToLogout, err)
	}

	return nil
}

// GetUserProfile получает профиль пользователя.
func (c *Client) GetUserProfile(ctx context.Context) (*authv1.UserProfileResponse, error) {
	log := logger.Log(ctx).With(zap.String("method", LogMethodGetUserProfile))

	// Получаем токен из контекста
	md, ok := metadata.FromIncomingContext(ctx)
	token := ""
	if ok && len(md["authorization"]) > 0 {
		token = md["authorization"][0]
	}

	// Создаем новый контекст с токеном для запроса в gRPC.
	outCtx := metadata.NewOutgoingContext(ctx, metadata.Pairs("authorization", token))

	resp, err := c.userClient.GetUserProfile(outCtx, &emptypb.Empty{})
	if err != nil {
		log.Error(ctx, ErrorFailedToGetProfile, zap.Error(err))
		return nil, fmt.Errorf("%s: %w", ErrorFailedToGetProfile, err)
	}

	return resp, nil
}

// Close закрывает соединение с gRPC сервером.
func (c *Client) Close() error {
	if c.conn != nil {
		err := c.conn.Close()
		if err != nil {
			return fmt.Errorf("failed to close grpc connection: %w", err)
		}
	}
	return nil
}
