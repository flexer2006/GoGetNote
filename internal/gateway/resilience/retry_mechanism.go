package resilience

import (
	"context"
	"errors"
	"fmt"
	"time"

	"gogetnote/pkg/logger"

	"go.uber.org/zap"
)

// RetryConfig содержит настройки для retry механизма.
type RetryConfig struct {
	// MaxAttempts - максимальное количество попыток (включая первую).
	MaxAttempts int
	// InitialBackoff - начальная задержка между попытками.
	InitialBackoff time.Duration
	// MaxBackoff - максимальная задержка между попытками.
	MaxBackoff time.Duration
	// BackoffFactor - множитель для экспоненциального отступа.
	BackoffFactor float64
	// ShouldRetry - функция для определения, нужно ли повторять запрос для данной ошибки.
	ShouldRetry func(error) bool
}

// DefaultRetryConfig возвращает конфигурацию retry механизма по умолчанию.
func DefaultRetryConfig() RetryConfig {
	return RetryConfig{
		MaxAttempts:    3,
		InitialBackoff: 100 * time.Millisecond,
		MaxBackoff:     1 * time.Second,
		BackoffFactor:  2.0,
		ShouldRetry:    defaultShouldRetry,
	}
}

// Ошибки retry механизма.
var (
	// ErrContextCanceled возвращается, когда контекст был отменен во время ожидания перед повторной попыткой.
	ErrContextCanceled = errors.New("context was canceled during retry")
)

// defaultShouldRetry определяет, следует ли повторять запрос по умолчанию.
func defaultShouldRetry(err error) bool {
	return !errors.Is(err, context.Canceled) && !errors.Is(err, context.DeadlineExceeded)
}

// Константы для логирования.
const (
	LogRetryOperation   = "retry operation"
	LogRetryAttempt     = "retry attempt"
	LogRetrySuccess     = "retry succeeded"
	LogRetryMaxAttempts = "retry max attempts reached"
)

// Retry выполняет функцию с повторными попытками.
type Retry struct {
	name   string
	config RetryConfig
}

// NewRetry создает новый экземпляр retry механизма.
func NewRetry(name string, config RetryConfig) *Retry {
	return &Retry{
		name:   name,
		config: config,
	}
}

// Execute выполняет функцию с автоматическими повторными попытками.
func (r *Retry) Execute(ctx context.Context, operation func() error) error {
	log := logger.Log(ctx).With(zap.String("retry", r.name))
	log.Debug(ctx, LogRetryOperation)

	var err error
	backoff := r.config.InitialBackoff
	attempts := 0

	for attempts < r.config.MaxAttempts {
		attempts++

		err = operation()

		if err == nil || !r.config.ShouldRetry(err) {
			if attempts > 1 && err == nil {
				log.Info(ctx, LogRetrySuccess, zap.Int("attempts", attempts))
			}
			return err
		}

		if attempts >= r.config.MaxAttempts {
			log.Warn(ctx, LogRetryMaxAttempts,
				zap.Int("attempts", attempts),
				zap.Error(err))
			return err
		}

		log.Info(ctx, LogRetryAttempt,
			zap.Int("attempt", attempts),
			zap.Duration("backoff", backoff),
			zap.Error(err))

		select {
		case <-time.After(backoff):
		case <-ctx.Done():
			return fmt.Errorf("%w: %w", ErrContextCanceled, ctx.Err())
		}

		backoff = time.Duration(float64(backoff) * r.config.BackoffFactor)
		if backoff > r.config.MaxBackoff {
			backoff = r.config.MaxBackoff
		}
	}

	return err
}
