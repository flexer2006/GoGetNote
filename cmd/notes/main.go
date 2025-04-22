// Package main реализует точку входа службы заметок.
package main

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"go.uber.org/zap"
	googlegrpc "google.golang.org/grpc"

	"gogetnote/internal/notes/adapters/grpc"
	"gogetnote/internal/notes/adapters/postgres"
	"gogetnote/internal/notes/adapters/services"
	"gogetnote/internal/notes/app"
	"gogetnote/internal/notes/config"
	"gogetnote/internal/notes/db"
	notesv1 "gogetnote/pkg/api/notes/v1"
	"gogetnote/pkg/logger"
	"gogetnote/pkg/shutdown"
)

// Константы для переменных окружения.
const (
	EnvLoggerMode  = "NOTES_LOGGER_MODE"
	EnvLoggerLevel = "NOTES_LOGGER_LEVEL"
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
	LogServiceStarted      = "note service started"
	LogServiceShutdownDone = "note service shutdown complete"
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
		log = finalLogger

		database, err := db.New(ctx, &cfg.Postgres, "migrations/notes")
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
		noteRepo := repoFactory.NoteRepository()

		log.Info(ctx, LogInitServices)
		tokenService := services.NewJWT(cfg.JWT.SecretKey)

		log.Info(ctx, LogInitUseCases)
		noteUseCase := app.NewNoteUseCase(noteRepo, tokenService)

		log.Info(ctx, LogInitHandlers)
		noteHandler := grpc.NewNoteHandler(noteUseCase)

		log.Info(ctx, LogInitGRPCServer)
		grpcServer := grpc.New(&cfg.GRPC)

		grpcServer.RegisterService(func(server *googlegrpc.Server) {
			notesv1.RegisterNoteServiceServer(server, noteHandler)
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
