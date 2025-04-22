package main

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/gofiber/fiber/v3"
	"go.uber.org/zap"

	"gogetnote/internal/gateway/adapters/cache"
	"gogetnote/internal/gateway/adapters/grpc/auth"
	httpServer "gogetnote/internal/gateway/app/http"
	"gogetnote/internal/gateway/app/services"
	"gogetnote/internal/gateway/config"
	"gogetnote/pkg/logger"
	"gogetnote/pkg/shutdown"
)

// Константы для переменных окружения.
const (
	EnvLoggerMode  = "GATEWAY_LOGGER_MODE"
	EnvLoggerLevel = "GATEWAY_LOGGER_LEVEL"
)

// Константы для сообщений об ошибках.
const (
	ErrInitLogger           = "failed to initialize logger"
	ErrSyncLogger           = "failed to sync logger"
	ErrLoadConfig           = "failed to load configuration"
	ErrInitLoggerWithConfig = "failed to initialize logger with configuration settings"
	ErrCreateAuthClient     = "failed to create auth client"
	ErrCreateRedisClient    = "failed to create Redis client"
	ErrStartHTTPServer      = "failed to start HTTP server"
)

// Константы для игнорируемых ошибок.
const (
	ErrSyncStderr = "sync /dev/stderr: invalid argument"
	ErrSyncStdout = "sync /dev/stdout: invalid argument"
)

// Константы для сообщений сервиса.
const (
	LogServiceStarted      = "gateway service started"
	LogServiceShutdownDone = "gateway service shutdown complete"
	LogStoppingHTTP        = "stopping HTTP server"
	LogInitClients         = "initializing gRPC clients"
	LogInitCache           = "initializing cache"
	LogInitServices        = "initializing services"
	LogInitHTTPServer      = "initializing HTTP server"
	LogStartingHTTP        = "starting HTTP server"
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
		log = finalLogger

		log.Info(ctx, LogServiceStarted,
			zap.String("environment", string(env)),
			zap.String("log_level", cfg.Logging.Level),
			zap.String("startup_time", time.Now().Format(time.RFC3339)))

		log.Info(ctx, LogInitClients)
		authClient, err := auth.NewAuthClient(&cfg.GRPC)
		if err != nil {
			log.Error(ctx, ErrCreateAuthClient, zap.Error(err))
			exitCode = 1
			return
		}

		// Инициализация Redis
		log.Info(ctx, LogInitCache)
		redisCache, err := cache.NewRedisCache(&cfg.Redis)
		if err != nil {
			log.Error(ctx, ErrCreateRedisClient, zap.Error(err))
			exitCode = 1
			return
		}

		log.Info(ctx, LogInitServices)
		authService := services.NewAuthService(authClient, redisCache)

		log.Info(ctx, LogInitHTTPServer)
		app := fiber.New(fiber.Config{
			ReadTimeout:  cfg.HTTP.ReadTimeout,
			WriteTimeout: cfg.HTTP.WriteTimeout,
		})

		httpServer.SetupRouter(app, authService)

		log.Info(ctx, LogStartingHTTP, zap.String("address", cfg.HTTP.GetAddress()))
		go func() {
			if err := app.Listen(cfg.HTTP.GetAddress()); err != nil {
				log.Error(ctx, ErrStartHTTPServer, zap.Error(err))
			}
		}()

		shutdown.Wait(ctx, cfg.Shutdown.GetTimeout(),
			// Закрытие gRPC клиентов.
			func(ctx context.Context) error {
				if client, ok := authClient.(*auth.Client); ok {
					log.Info(ctx, "Closing auth client")
					return client.Close()
				}
				return nil
			},
			// Закрытие Redis соединения.
			func(ctx context.Context) error {
				log.Info(ctx, "Closing Redis connection")
				return redisCache.Close()
			},
			// Остановка HTTP сервера.
			func(ctx context.Context) error {
				log.Info(ctx, LogStoppingHTTP)
				return app.Shutdown()
			},
		)

		log.Info(ctx, LogServiceShutdownDone)
	}()

	if exitCode != 0 {
		os.Exit(exitCode)
	}
}
