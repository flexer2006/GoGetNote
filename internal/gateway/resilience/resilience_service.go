package resilience

import (
	"context"

	"gogetnote/pkg/logger"

	"go.uber.org/zap"
)

// ServiceResilience обеспечивает отказоустойчивость сервисных вызовов.
type ServiceResilience struct {
	serviceName    string
	circuitBreaker *CircuitBreaker
	retry          *Retry
}

// NewServiceResilience создает новую обертку отказоустойчивости для сервиса.
func NewServiceResilience(serviceName string) *ServiceResilience {
	return &ServiceResilience{
		serviceName:    serviceName,
		circuitBreaker: NewCircuitBreaker(serviceName, DefaultCircuitBreakerConfig()),
		retry:          NewRetry(serviceName, DefaultRetryConfig()),
	}
}

// ExecuteWithResilience выполняет операцию с отказоустойчивостью.
func (r *ServiceResilience) ExecuteWithResilience(
	ctx context.Context,
	operationName string,
	operation func() error,
) error {
	log := logger.Log(ctx).With(
		zap.String("service", r.serviceName),
		zap.String("operation", operationName),
	)
	log.Debug(ctx, "Executing operation with resilience")

	return r.circuitBreaker.Execute(ctx, func() error {
		return r.retry.Execute(ctx, operation)
	})
}

// ExecuteWithResultTokenResponse выполняет операцию с отказоустойчивостью и возвращает TokenResponse.
func (r *ServiceResilience) ExecuteWithResultTokenResponse(
	ctx context.Context,
	operationName string,
	operation func() (interface{}, error),
) (interface{}, error) {
	log := logger.Log(ctx).With(
		zap.String("service", r.serviceName),
		zap.String("operation", operationName),
	)
	log.Debug(ctx, "Executing operation with resilience and result")

	var result interface{}
	var resultErr error

	err := r.circuitBreaker.Execute(ctx, func() error {
		return r.retry.Execute(ctx, func() error {
			var err error
			result, err = operation()
			if err != nil {
				log.Warn(ctx, "Operation failed", zap.Error(err))
				return err
			}
			return nil
		})
	})

	if err != nil {
		return nil, err
	}

	return result, resultErr
}
