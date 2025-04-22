// Package resilience содержит механизмы обеспечения отказоустойчивости
package resilience

import (
	"context"
	"errors"
	"sync"
	"time"

	"gogetnote/pkg/logger"

	"go.uber.org/zap"
)

// CircuitState представляет состояние Circuit Breaker.
type CircuitState int

// Состояния Circuit Breaker.
const (
	// StateClosed - нормальное состояние, запросы проходят.
	StateClosed CircuitState = iota
	// StateOpen - состояние отказа, запросы блокируются.
	StateOpen
	// StateHalfOpen - промежуточное состояние, пробные запросы.
	StateHalfOpen
)

// Константы для логирования.
const (
	LogCircuitStateChange = "circuit breaker state changed"
	LogCircuitTrip        = "circuit breaker tripped"
	LogCircuitReset       = "circuit breaker reset"
	LogCircuitAllowRetry  = "circuit breaker allowing retry"
	LogCircuitReject      = "circuit breaker rejected request"
)

// Ошибки Circuit Breaker.
var (
	// ErrCircuitOpen возвращается, когда Circuit Breaker находится в открытом состоянии.
	ErrCircuitOpen = errors.New("circuit breaker is open")
)

// CircuitBreakerConfig содержит настройки Circuit Breaker.
type CircuitBreakerConfig struct {
	// ErrorThreshold - максимальное количество ошибок перед переключением в открытое состояние.
	ErrorThreshold int
	// Timeout - таймаут после которого Circuit Breaker переходит в полуоткрытое состояние.
	Timeout time.Duration
	// SuccessThreshold - максимальное количество успешных запросов для перехода в закрытое состояние.
	SuccessThreshold int
}

// DefaultCircuitBreakerConfig возвращает конфигурацию Circuit Breaker по умолчанию.
func DefaultCircuitBreakerConfig() CircuitBreakerConfig {
	return CircuitBreakerConfig{
		ErrorThreshold:   5,                // После 5 ошибок переходим в открытое состояние.
		Timeout:          10 * time.Second, // Через 10 секунд пытаемся восстановиться.
		SuccessThreshold: 2,                // После 2 успешных запросов переходим в закрытое состояние.
	}
}

// CircuitBreaker реализует паттерн Circuit Breaker.
type CircuitBreaker struct {
	name string
	mu   sync.RWMutex

	state           CircuitState
	config          CircuitBreakerConfig
	failures        int
	successes       int
	lastStateChange time.Time
}

// NewCircuitBreaker создает новый экземпляр Circuit Breaker.
func NewCircuitBreaker(name string, config CircuitBreakerConfig) *CircuitBreaker {
	return &CircuitBreaker{
		name:            name,
		state:           StateClosed,
		config:          config,
		failures:        0,
		successes:       0,
		lastStateChange: time.Now(),
	}
}

// Execute выполняет функцию с защитой Circuit Breaker.
func (cb *CircuitBreaker) Execute(ctx context.Context, fn func() error) error {
	if !cb.AllowRequest(ctx) {
		return ErrCircuitOpen
	}

	err := fn()
	cb.RecordResult(ctx, err)
	return err
}

// AllowRequest проверяет возможность выполнения запроса.
func (cb *CircuitBreaker) AllowRequest(ctx context.Context) bool {
	cb.mu.RLock()
	defer cb.mu.RUnlock()

	log := logger.Log(ctx).With(
		zap.String("circuit_breaker", cb.name),
		zap.Int("circuit_state", int(cb.state)),
	)

	switch cb.state {
	case StateClosed:
		return true
	case StateOpen:
		if time.Since(cb.lastStateChange) > cb.config.Timeout {
			cb.mu.RUnlock()
			cb.mu.Lock()
			defer cb.mu.Unlock()

			if cb.state == StateOpen && time.Since(cb.lastStateChange) > cb.config.Timeout {
				cb.state = StateHalfOpen
				cb.lastStateChange = time.Now()
				log.Info(ctx, LogCircuitStateChange, zap.Int("new_state", int(StateHalfOpen)))
				log.Info(ctx, LogCircuitAllowRetry)
				return true
			}
			return false
		}
		log.Info(ctx, LogCircuitReject)
		return false
	case StateHalfOpen:
		log.Info(ctx, LogCircuitAllowRetry)
		return true
	default:
		return false
	}
}

// RecordResult записывает результат выполнения функции.
func (cb *CircuitBreaker) RecordResult(ctx context.Context, err error) {
	cb.mu.Lock()
	defer cb.mu.Unlock()

	log := logger.Log(ctx).With(
		zap.String("circuit_breaker", cb.name),
		zap.Int("circuit_state", int(cb.state)),
	)

	if err != nil {
		cb.onFailure(ctx, log)
		return
	}

	cb.onSuccess(ctx, log)
}

// onFailure обрабатывает неудачный запрос.
func (cb *CircuitBreaker) onFailure(ctx context.Context, log *logger.Logger) {
	switch cb.state {
	case StateClosed:
		cb.failures++
		if cb.failures >= cb.config.ErrorThreshold {
			cb.tripBreaker(ctx, log)
		}
	case StateHalfOpen:
		cb.tripBreaker(ctx, log)
	}
}

// onSuccess обрабатывает успешный запрос.
func (cb *CircuitBreaker) onSuccess(ctx context.Context, log *logger.Logger) {
	switch cb.state {
	case StateClosed:
		cb.failures = 0
	case StateHalfOpen:
		cb.successes++
		if cb.successes >= cb.config.SuccessThreshold {
			cb.resetBreaker(ctx, log)
		}
	}
}

// tripBreaker переключает Circuit Breaker в открытое состояние.
func (cb *CircuitBreaker) tripBreaker(ctx context.Context, log *logger.Logger) {
	if cb.state != StateOpen {
		log.Warn(ctx, LogCircuitTrip, zap.Int("failures", cb.failures))
		cb.state = StateOpen
		cb.lastStateChange = time.Now()
		cb.successes = 0
		log.Info(ctx, LogCircuitStateChange, zap.Int("new_state", int(StateOpen)))
	}
}

// resetBreaker переключает Circuit Breaker в закрытое состояние.
func (cb *CircuitBreaker) resetBreaker(ctx context.Context, log *logger.Logger) {
	log.Info(ctx, LogCircuitReset)
	cb.state = StateClosed
	cb.lastStateChange = time.Now()
	cb.failures = 0
	cb.successes = 0
	log.Info(ctx, LogCircuitStateChange, zap.Int("new_state", int(StateClosed)))
}

// GetState возвращает текущее состояние Circuit Breaker.
func (cb *CircuitBreaker) GetState() CircuitState {
	cb.mu.RLock()
	defer cb.mu.RUnlock()
	return cb.state
}
