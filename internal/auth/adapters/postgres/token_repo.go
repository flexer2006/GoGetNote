package postgres

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
	"go.uber.org/zap"

	"gogetnote/internal/auth/domain/services"
	"gogetnote/internal/auth/ports/repositories"
	"gogetnote/pkg/logger"
)

// TokenRepository реализует интерфейс repositories.TokenRepository для работы с Postgres.
type TokenRepository struct {
	pool PgxPoolInterface
}

// NewTokenRepository создает новый экземпляр репозитория токенов.
func NewTokenRepository(pool PgxPoolInterface) repositories.TokenRepository {
	return &TokenRepository{pool: pool}
}

// FindByToken находит токен по его значению.
func (r *TokenRepository) FindByToken(ctx context.Context, token string) (*services.RefreshToken, error) {
	log := logger.Log(ctx).With(zap.String("repository", "token"), zap.String("method", "FindByToken"))

	query := `
        SELECT id, user_id, token, expires_at, created_at, is_revoked
        FROM refresh_tokens
        WHERE token = $1
    `

	var refreshToken services.RefreshToken
	var idn string // UUID в формате строки

	err := r.pool.QueryRow(ctx, query, token).Scan(
		&idn,
		&refreshToken.UserID,
		&refreshToken.Token,
		&refreshToken.ExpiresAt,
		&refreshToken.CreatedAt,
		&refreshToken.IsRevoked,
	)

	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			log.Debug(ctx, "token not found")
			return nil, services.ErrInvalidRefreshToken
		}
		log.Error(ctx, "error finding refresh token", zap.Error(err))
		return nil, fmt.Errorf("error querying refresh token: %w", err)
	}

	refreshToken.ID = idn

	return &refreshToken, nil
}

// StoreRefreshToken сохраняет новый refresh токен в БД.
func (r *TokenRepository) StoreRefreshToken(ctx context.Context, token *services.RefreshToken) error {
	log := logger.Log(ctx).With(zap.String("repository", "token"), zap.String("method", "StoreRefreshToken"))

	query := `
        INSERT INTO refresh_tokens (user_id, token, expires_at, is_revoked)
        VALUES ($1, $2, $3, $4)
    `

	_, err := r.pool.Exec(ctx, query,
		token.UserID,
		token.Token,
		token.ExpiresAt,
		token.IsRevoked,
	)

	if err != nil {
		log.Error(ctx, "error storing refresh token", zap.Error(err))
		return fmt.Errorf("error storing refresh token: %w", err)
	}

	return nil
}

// RevokeToken отзывает refresh токен.
func (r *TokenRepository) RevokeToken(ctx context.Context, token string) error {
	log := logger.Log(ctx).With(zap.String("repository", "token"), zap.String("method", "RevokeToken"))

	query := `
        UPDATE refresh_tokens
        SET is_revoked = true
        WHERE token = $1
    `

	result, err := r.pool.Exec(ctx, query, token)
	if err != nil {
		log.Error(ctx, "error revoking refresh token", zap.Error(err))
		return fmt.Errorf("error revoking refresh token: %w", err)
	}

	if result.RowsAffected() == 0 {
		log.Debug(ctx, "token not found for revocation")
		return services.ErrInvalidRefreshToken
	}

	return nil
}

// CleanupExpiredTokens удаляет просроченные токены.
func (r *TokenRepository) CleanupExpiredTokens(ctx context.Context) error {
	log := logger.Log(ctx).With(zap.String("repository", "token"), zap.String("method", "CleanupExpiredTokens"))

	query := `
        DELETE FROM refresh_tokens
        WHERE expires_at < NOW() OR is_revoked = true
    `

	result, err := r.pool.Exec(ctx, query)
	if err != nil {
		log.Error(ctx, "error cleaning up expired tokens", zap.Error(err))
		return fmt.Errorf("error cleaning up expired tokens: %w", err)
	}

	log.Info(ctx, "expired tokens cleaned up", zap.Int64("removed_count", result.RowsAffected()))
	return nil
}

// FindUserTokens возвращает все токены пользователя.
func (r *TokenRepository) FindUserTokens(ctx context.Context, userID string) ([]*services.RefreshToken, error) {
	log := logger.Log(ctx).With(
		zap.String("repository", "token"),
		zap.String("method", "FindUserTokens"),
		zap.String("userID", userID),
	)

	query := `
        SELECT id, user_id, token, expires_at, created_at, is_revoked
        FROM refresh_tokens
        WHERE user_id = $1
        ORDER BY created_at DESC
    `

	rows, err := r.pool.Query(ctx, query, userID)
	if err != nil {
		log.Error(ctx, "error querying user tokens", zap.Error(err))
		return nil, fmt.Errorf("error querying user tokens: %w", err)
	}
	defer rows.Close()

	var tokens []*services.RefreshToken

	for rows.Next() {
		var token services.RefreshToken
		var idn string

		err := rows.Scan(
			&idn,
			&token.UserID,
			&token.Token,
			&token.ExpiresAt,
			&token.CreatedAt,
			&token.IsRevoked,
		)

		if err != nil {
			log.Error(ctx, "error scanning token row", zap.Error(err))
			return nil, fmt.Errorf("error scanning token row: %w", err)
		}

		token.ID = idn
		tokens = append(tokens, &token)
	}

	if err = rows.Err(); err != nil {
		log.Error(ctx, "error iterating token rows", zap.Error(err))
		return nil, fmt.Errorf("error iterating token rows: %w", err)
	}

	return tokens, nil
}

// RevokeAllUserTokens отзывает все токены пользователя.
func (r *TokenRepository) RevokeAllUserTokens(ctx context.Context, userID string) error {
	log := logger.Log(ctx).With(
		zap.String("repository", "token"),
		zap.String("method", "RevokeAllUserTokens"),
		zap.String("userID", userID),
	)

	query := `
        UPDATE refresh_tokens
        SET is_revoked = true
        WHERE user_id = $1 AND is_revoked = false
    `

	result, err := r.pool.Exec(ctx, query, userID)
	if err != nil {
		log.Error(ctx, "error revoking all user tokens", zap.Error(err))
		return fmt.Errorf("error revoking all user tokens: %w", err)
	}

	log.Info(ctx, "all user tokens revoked", zap.Int64("count", result.RowsAffected()))
	return nil
}
