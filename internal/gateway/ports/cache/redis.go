// Package cache определяет интерфейсы для кэширования.
package cache

import (
	"context"
	"time"
)

// Cache определяет интерфейс для работы с кэшем.
type Cache interface {
	Get(ctx context.Context, key string) (string, error)

	Set(ctx context.Context, key string, value string, ttl time.Duration) error

	Delete(ctx context.Context, key string) error

	Close() error
}
