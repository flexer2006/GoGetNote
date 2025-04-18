package main

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"gogetnote/internal/auth/config"
	"gogetnote/internal/auth/db"
	"gogetnote/pkg/logger"
	"gogetnote/pkg/shutdown"

	"go.uber.org/zap"
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
	LogStoppingHTTP        = "stopping HTTP server"
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

	defer func() {
		if err := log.Sync(); err != nil {
			if err.Error() != ErrSyncStderr && err.Error() != ErrSyncStdout {
				if _, writeErr := fmt.Fprintf(os.Stderr, "%s: %v\n", ErrSyncLogger, err); writeErr != nil {
					panic(writeErr)
				}
			}
		}
	}()

	cfg, err := config.Load(ctx)
	if err != nil {
		log.Fatal(ctx, ErrLoadConfig, zap.Error(err))
	}

	finalLogger, err := logger.NewLogger(cfg.Logging.GetEnvironment(), cfg.Logging.Level)
	if err != nil {
		log.Fatal(ctx, ErrInitLoggerWithConfig, zap.Error(err))
	}
	logger.SetGlobalLogger(finalLogger)

	database, err := db.New(ctx, &cfg.Postgres, "migrations/auth")
	if err != nil {
		log.Fatal(ctx, ErrInitDB, zap.Error(err))
	}

	log.Info(ctx, LogServiceStarted,
		zap.String("environment", string(env)),
		zap.String("log_level", cfg.Logging.Level),
		zap.String("startup_time", time.Now().Format(time.RFC3339)))

	// Здесь вы бы инициализировали и запускали другие компоненты системы:
	// - HTTP сервер
	// - gRPC сервер
	// - и т.д.

	// Настраиваем graceful shutdown с timeout из конфигурации
	shutdown.Wait(cfg.Shutdown.GetTimeout(),
		// Здесь добавьте функции для graceful shutdown ваших компонентов:
		func(ctx context.Context) error {
			log.Info(ctx, LogClosingDB)
			database.Close(ctx)
			return nil
		},
		func(ctx context.Context) error {
			log.Info(ctx, LogStoppingHTTP)
			// Например: server.Shutdown(ctx)
			return nil
		},
	)

	log.Info(ctx, LogServiceShutdownDone)
}
