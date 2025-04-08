package logger

import (
	"context"
	"fmt"
)

type contextKey string

const (
	Key contextKey = "logger"
)

func NewContext(ctx context.Context, logger *Logger) context.Context {
	return context.WithValue(ctx, Key, logger)
}

func FromContext(ctx context.Context) (*Logger, error) {
	logger, ok := ctx.Value(Key).(*Logger)
	if !ok {
		return nil, fmt.Errorf("logger not found in context")
	}
	return logger, nil
}
