// Package notes содержит реализацию gRPC-клиента для взаимодействия с сервисом заметок.
package notes

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/grpc/connectivity"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"

	"gogetnote/internal/gateway/config"
	grpcPort "gogetnote/internal/gateway/ports/grpc"
	notesv1 "gogetnote/pkg/api/notes/v1"
	"gogetnote/pkg/logger"
)

// Константы для логирования.
const (
	LogMethodCreateNote = "CreateNote"
	LogMethodGetNote    = "GetNote"
	LogMethodListNotes  = "ListNotes"
	LogMethodUpdateNote = "UpdateNote"
	LogMethodDeleteNote = "DeleteNote"

	ErrorFailedToCreateNote = "failed to create note"
	ErrorFailedToGetNote    = "failed to get note"
	ErrorFailedToListNotes  = "failed to list notes"
	ErrorFailedToUpdateNote = "failed to update note"
	ErrorFailedToDeleteNote = "failed to delete note"
)

// ErrNotesServiceConnectionTimeout представляет ошибку таймаута соединения с сервисом заметок.
var ErrNotesServiceConnectionTimeout = errors.New("connection timeout: failed to connect to notes service")

// Client реализует интерфейс NotesServiceClient.
type Client struct {
	notesClient notesv1.NoteServiceClient
	conn        *grpc.ClientConn
}

// NewNotesClient создает новый экземпляр клиента заметок.
func NewNotesClient(ctx context.Context, cfg *config.GRPCClientConfig) (grpcPort.NotesServiceClient, error) {
	conn, err := grpc.NewClient(
		cfg.NotesService.GetAddress(),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to notes service: %w", err)
	}

	// Use the provided context instead of creating a new one
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
			return nil, ErrNotesServiceConnectionTimeout
		}
	}

	return &Client{
		notesClient: notesv1.NewNoteServiceClient(conn),
		conn:        conn,
	}, nil
}

// formatAuthorizationToken formats the authorization token by adding "Bearer " prefix if not present.
func formatAuthorizationToken(token string) string {
	if token == "" {
		return ""
	}
	// If the token doesn't start with "Bearer ", add it
	if !strings.HasPrefix(token, "Bearer ") {
		return "Bearer " + token
	}
	return token
}

// CreateNote создает новую заметку.
func (c *Client) CreateNote(ctx context.Context, title, content string) (*notesv1.NoteResponse, error) {
	log := logger.Log(ctx).With(zap.String("method", LogMethodCreateNote))

	// Создаем запрос
	req := &notesv1.CreateNoteRequest{
		Title:   title,
		Content: content,
	}

	// Получаем токен из контекста и добавляем его в исходящий контекст
	md, ok := metadata.FromIncomingContext(ctx)
	token := ""
	if ok && len(md["authorization"]) > 0 {
		token = md["authorization"][0]
	}
	log.Debug(ctx, "Sending token to notes service",
		zap.String("raw_token", token))
	formattedToken := formatAuthorizationToken(token)
	log.Debug(ctx, "Token after formatting",
		zap.String("formatted_token", formattedToken))
	outCtx := metadata.NewOutgoingContext(ctx, metadata.Pairs("authorization", formattedToken))

	// Выполняем запрос
	resp, err := c.notesClient.CreateNote(outCtx, req)
	if err != nil {
		log.Error(ctx, ErrorFailedToCreateNote, zap.Error(err))
		return nil, fmt.Errorf("%s: %w", ErrorFailedToCreateNote, err)
	}

	return resp, nil
}

// GetNote получает заметку по ID.
func (c *Client) GetNote(ctx context.Context, noteID string) (*notesv1.NoteResponse, error) {
	log := logger.Log(ctx).With(zap.String("method", LogMethodGetNote))

	req := &notesv1.GetNoteRequest{
		NoteId: noteID,
	}

	// Получаем токен из контекста и добавляем его в исходящий контекст
	md, ok := metadata.FromIncomingContext(ctx)
	token := ""
	if ok && len(md["authorization"]) > 0 {
		token = md["authorization"][0]
	}
	log.Debug(ctx, "Sending token to notes service",
		zap.String("raw_token", token))
	formattedToken := formatAuthorizationToken(token)
	log.Debug(ctx, "Token after formatting",
		zap.String("formatted_token", formattedToken))
	outCtx := metadata.NewOutgoingContext(ctx, metadata.Pairs("authorization", formattedToken))

	resp, err := c.notesClient.GetNote(outCtx, req)
	if err != nil {
		log.Error(ctx, ErrorFailedToGetNote, zap.Error(err))
		return nil, fmt.Errorf("%s: %w", ErrorFailedToGetNote, err)
	}

	return resp, nil
}

// ListNotes получает список заметок с пагинацией.
func (c *Client) ListNotes(ctx context.Context, limit, offset int32) (*notesv1.ListNotesResponse, error) {
	log := logger.Log(ctx).With(zap.String("method", LogMethodListNotes))

	req := &notesv1.ListNotesRequest{
		Limit:  limit,
		Offset: offset,
	}

	// Получаем токен из контекста и добавляем его в исходящий контекст
	md, ok := metadata.FromIncomingContext(ctx)
	token := ""
	if ok && len(md["authorization"]) > 0 {
		token = md["authorization"][0]
	}
	log.Debug(ctx, "Sending token to notes service",
		zap.String("raw_token", token))
	formattedToken := formatAuthorizationToken(token)
	log.Debug(ctx, "Token after formatting",
		zap.String("formatted_token", formattedToken))
	outCtx := metadata.NewOutgoingContext(ctx, metadata.Pairs("authorization", formattedToken))

	resp, err := c.notesClient.ListNotes(outCtx, req)
	if err != nil {
		log.Error(ctx, ErrorFailedToListNotes, zap.Error(err))
		return nil, fmt.Errorf("%s: %w", ErrorFailedToListNotes, err)
	}

	return resp, nil
}

// UpdateNote обновляет существующую заметку.
func (c *Client) UpdateNote(ctx context.Context, noteID string, title, content *string) (*notesv1.NoteResponse, error) {
	log := logger.Log(ctx).With(zap.String("method", LogMethodUpdateNote))

	req := &notesv1.UpdateNoteRequest{
		NoteId:  noteID,
		Title:   title,
		Content: content,
	}

	// Получаем токен из контекста и добавляем его в исходящий контекст
	md, ok := metadata.FromIncomingContext(ctx)
	token := ""
	if ok && len(md["authorization"]) > 0 {
		token = md["authorization"][0]
	}
	log.Debug(ctx, "Sending token to notes service",
		zap.String("raw_token", token))
	formattedToken := formatAuthorizationToken(token)
	log.Debug(ctx, "Token after formatting",
		zap.String("formatted_token", formattedToken))
	outCtx := metadata.NewOutgoingContext(ctx, metadata.Pairs("authorization", formattedToken))

	resp, err := c.notesClient.UpdateNote(outCtx, req)
	if err != nil {
		log.Error(ctx, ErrorFailedToUpdateNote, zap.Error(err))
		return nil, fmt.Errorf("%s: %w", ErrorFailedToUpdateNote, err)
	}

	return resp, nil
}

// DeleteNote удаляет заметку.
func (c *Client) DeleteNote(ctx context.Context, noteID string) error {
	log := logger.Log(ctx).With(zap.String("method", LogMethodDeleteNote))

	req := &notesv1.DeleteNoteRequest{
		NoteId: noteID,
	}

	// Получаем токен из контекста и добавляем его в исходящий контекст
	md, ok := metadata.FromIncomingContext(ctx)
	token := ""
	if ok && len(md["authorization"]) > 0 {
		token = md["authorization"][0]
	}
	log.Debug(ctx, "Sending token to notes service",
		zap.String("raw_token", token))
	formattedToken := formatAuthorizationToken(token)
	log.Debug(ctx, "Token after formatting",
		zap.String("formatted_token", formattedToken))
	outCtx := metadata.NewOutgoingContext(ctx, metadata.Pairs("authorization", formattedToken))

	_, err := c.notesClient.DeleteNote(outCtx, req)
	if err != nil {
		log.Error(ctx, ErrorFailedToDeleteNote, zap.Error(err))
		return fmt.Errorf("%s: %w", ErrorFailedToDeleteNote, err)
	}

	return nil
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
