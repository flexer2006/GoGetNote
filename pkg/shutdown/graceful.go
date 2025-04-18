// Package shutdown предоставляет функциональность для корректного завершения приложения
// путем ожидания и обработки сигналов SIGINT и SIGTERM.
package shutdown

import (
	"context"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"
)

// Wait блокирует выполнение до получения сигнала SIGINT или SIGTERM,
// затем выполняет все хуки в рамках заданного timeout.
func Wait(timeout time.Duration, hooks ...func(context.Context) error) {
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	<-sigCh

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	var wgp sync.WaitGroup
	for _, hook := range hooks {
		wgp.Add(1)
		go func(fn func(context.Context) error) {
			defer wgp.Done()
			_ = fn(ctx)
		}(hook)
	}

	done := make(chan struct{})
	go func() {
		wgp.Wait()
		close(done)
	}()

	select {
	case <-done:
	case <-ctx.Done():
	}
}
