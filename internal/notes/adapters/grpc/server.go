package grpc

import (
	"context"
	"fmt"
	"net"

	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/grpc/reflection"

	"gogetnote/internal/notes/config"
	"gogetnote/pkg/logger"
)

// Server представляет gRPC сервер.
type Server struct {
	server   *grpc.Server
	address  string
	listener net.Listener
}

// New создает новый экземпляр gRPC сервера.
func New(config *config.GRPCConfig) *Server {
	address := config.GetAddress()
	return &Server{
		server:  grpc.NewServer(),
		address: address,
	}
}

// RegisterService регистрирует gRPC сервисы.
func (s *Server) RegisterService(registerFunc func(*grpc.Server)) {
	registerFunc(s.server)
	reflection.Register(s.server)
}

// Start запускает gRPC сервер.
func (s *Server) Start(ctx context.Context) error {
	log := logger.Log(ctx)

	listener, err := net.Listen("tcp", s.address)
	if err != nil {
		return fmt.Errorf("failed to listen: %w", err)
	}
	s.listener = listener

	log.Info(ctx, "gRPC server started", zap.String("address", s.address))

	go func() {
		if err := s.server.Serve(listener); err != nil {
			log.Error(ctx, "failed to serve gRPC", zap.Error(err))
		}
	}()

	return nil
}

// Stop останавливает gRPC сервер.
func (s *Server) Stop(ctx context.Context) {
	log := logger.Log(ctx)
	log.Info(ctx, "stopping gRPC server")

	s.server.GracefulStop()
	if s.listener != nil {
		if err := s.listener.Close(); err != nil {
			log.Error(ctx, "failed to close listener", zap.Error(err))
		}
	}
}
