// Package grpc предоставляет реализацию gRPC сервера для аутентификационного сервиса.
package grpc

import (
	"context"
	"fmt"
	"net"

	"google.golang.org/grpc"
	"google.golang.org/grpc/reflection"

	"gogetnote/internal/auth/config"
	"gogetnote/pkg/logger"

	"go.uber.org/zap"
)

// Константы для логирования.
const (
	LogServerStarting = "Starting gRPC server"
	LogServerStarted  = "gRPC server started"
	LogServerStopping = "Stopping gRPC server"
	LogServerStopped  = "gRPC server stopped"
	ErrServerStart    = "failed to start gRPC server"
)

// Server представляет gRPC сервер.
type Server struct {
	cfg    *config.GRPCConfig
	server *grpc.Server
}

// New создает новый экземпляр gRPC сервера.
func New(cfg *config.GRPCConfig) *Server {
	return &Server{
		cfg:    cfg,
		server: grpc.NewServer(),
	}
}

// Start запускает gRPC сервер.
func (s *Server) Start(ctx context.Context) error {
	log := logger.Log(ctx)
	address := s.cfg.GetAddress()

	log.Info(ctx, LogServerStarting, zap.String("address", address))

	listener, err := net.Listen("tcp", address)
	if err != nil {
		log.Error(ctx, ErrServerStart, zap.Error(err))
		return fmt.Errorf("%s: %w", ErrServerStart, err)
	}

	reflection.Register(s.server)

	go func() {
		if err := s.server.Serve(listener); err != nil {
			log.Error(ctx, ErrServerStart, zap.Error(err))
		}
	}()

	log.Info(ctx, LogServerStarted, zap.String("address", address))
	return nil
}

// Stop останавливает gRPC сервер.
func (s *Server) Stop(ctx context.Context) {
	log := logger.Log(ctx)

	log.Info(ctx, LogServerStopping)
	s.server.GracefulStop()
	log.Info(ctx, LogServerStopped)
}

// RegisterService регистрирует gRPC сервис в сервере.
func (s *Server) RegisterService(registerFn func(server *grpc.Server)) {
	registerFn(s.server)
}

// RegisterGRPCService регистрирует gRPC сервис в сервере используя дескриптор сервиса.
func (s *Server) RegisterGRPCService(desc *grpc.ServiceDesc, impl interface{}) {
	s.server.RegisterService(desc, impl)
}
