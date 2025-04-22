// Package main реализует точку входа службы аутентификации.
package main

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"gogetnote/internal/auth/adapters/grpc"
	"gogetnote/internal/auth/adapters/postgres"
	"gogetnote/internal/auth/adapters/services"
	"gogetnote/internal/auth/app"
	"gogetnote/internal/auth/config"
	"gogetnote/internal/auth/db"
	authv1 "gogetnote/pkg/api/auth/v1"
	"gogetnote/pkg/logger"
	"gogetnote/pkg/shutdown"

	"go.uber.org/zap"
	googlegrpc "google.golang.org/grpc"
)

// Константы для переменных окружения.
const (
	EnvLoggerMode  = "AUTH_LOGGER_MODE"
	EnvLoggerLevel = "AUTH_LOGGER_LEVEL"
)

// Константы для сообщений об ошибках.
const (
	ErrInitLogger           = "failed to initialize logger"
	ErrSyncLogger           = "failed to sync logger"
	ErrLoadConfig           = "failed to load configuration"
	ErrInitLoggerWithConfig = "failed to initialize logger with configuration settings"
	ErrInitDB               = "failed to initialize database"
	ErrStartGRPC            = "failed to start gRPC server"
)

// Константы для игнорируемых ошибок.
const (
	ErrSyncStderr = "sync /dev/stderr: invalid argument"
	ErrSyncStdout = "sync /dev/stdout: invalid argument"
)

// Константы для сообщений сервиса.
const (
	LogServiceStarted      = "authentication service started"
	LogServiceShutdownDone = "authentication service shutdown complete"
	LogClosingDB           = "closing database connections"
	LogStoppingGRPC        = "stopping gRPC server"
	LogInitRepo            = "initializing repositories"
	LogInitServices        = "initializing services"
	LogInitUseCases        = "initializing use cases"
	LogInitHandlers        = "initializing gRPC handlers"
	LogInitGRPCServer      = "initializing gRPC server"
	LogStartingGRPC        = "starting gRPC server"
)

func main() {
	env := logger.Development
	if strings.ToLower(os.Getenv(EnvLoggerMode)) == "production" {
		env = logger.Production
	}

	log, err := logger.NewLogger(env, os.Getenv(EnvLoggerLevel))
	if err != nil {
		panic(ErrInitLogger + ": " + err.Error())
	}

	logger.SetGlobalLogger(log)

	ctx := logger.NewRequestIDContext(context.Background(), "")

	var exitCode int

	func() {
		defer func() {
			if err := log.Sync(); err != nil {
				errMsg := err.Error()
				if strings.Contains(errMsg, ErrSyncStderr) || strings.Contains(errMsg, ErrSyncStdout) {
					return
				}
				if _, writeErr := fmt.Fprintf(os.Stderr, "%s: %v\n", ErrSyncLogger, err); writeErr != nil {
					panic(writeErr)
				}
			}
		}()

		cfg, err := config.Load(ctx)
		if err != nil {
			log.Error(ctx, ErrLoadConfig, zap.Error(err))
			exitCode = 1
			return
		}

		finalLogger, err := logger.NewLogger(cfg.Logging.GetEnvironment(), cfg.Logging.Level)
		if err != nil {
			log.Error(ctx, ErrInitLoggerWithConfig, zap.Error(err))
			exitCode = 1
			return
		}
		logger.SetGlobalLogger(finalLogger)

		database, err := db.New(ctx, &cfg.Postgres, "migrations/auth")
		if err != nil {
			log.Error(ctx, ErrInitDB, zap.Error(err))
			exitCode = 1
			return
		}

		log.Info(ctx, LogServiceStarted,
			zap.String("environment", string(env)),
			zap.String("log_level", cfg.Logging.Level),
			zap.String("startup_time", time.Now().Format(time.RFC3339)))

		log.Info(ctx, LogInitRepo)
		repoFactory := postgres.NewRepositoryFactory(database.Pool())
		userRepo := repoFactory.UserRepository()
		tokenRepo := repoFactory.TokenRepository()

		log.Info(ctx, LogInitServices)
		serviceFactory := services.NewServiceFactory(
			cfg.JWT.SecretKey,
			cfg.JWT.GetAccessTokenTTL(),
			cfg.JWT.GetRefreshTokenTTL(),
			cfg.JWT.BCryptCost,
		)
		passwordService := serviceFactory.PasswordService()
		tokenService := serviceFactory.TokenService()

		log.Info(ctx, LogInitUseCases)
		authUseCase := app.NewAuthUseCase(userRepo, tokenRepo, passwordService, tokenService)
		userUseCase := app.NewUserUseCase(userRepo)

		log.Info(ctx, LogInitHandlers)
		authHandler := grpc.NewAuthHandler(authUseCase)
		userHandler := grpc.NewUserHandler(userUseCase, tokenService)

		log.Info(ctx, LogInitGRPCServer)
		grpcServer := grpc.New(&cfg.GRPC)

		// Регистрация сервисов.
		grpcServer.RegisterService(func(server *googlegrpc.Server) {
			authv1.RegisterAuthServiceServer(server, authHandler)
			authv1.RegisterUserServiceServer(server, userHandler)
		})

		log.Info(ctx, LogStartingGRPC)
		if err := grpcServer.Start(ctx); err != nil {
			log.Error(ctx, ErrStartGRPC, zap.Error(err))
			exitCode = 1
			return
		}

		shutdown.Wait(ctx, cfg.Shutdown.GetTimeout(),
			func(ctx context.Context) error {
				log.Info(ctx, LogClosingDB)
				database.Close(ctx)
				return nil
			},
			func(ctx context.Context) error {
				log.Info(ctx, LogStoppingGRPC)
				grpcServer.Stop(ctx)
				return nil
			},
		)

		log.Info(ctx, LogServiceShutdownDone)
	}()

	if exitCode != 0 {
		os.Exit(exitCode)
	}
}
