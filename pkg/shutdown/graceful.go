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

	var wg sync.WaitGroup
	for _, hook := range hooks {
		wg.Add(1)
		go func(fn func(context.Context) error) {
			defer wg.Done()
			_ = fn(ctx)
		}(hook)
	}

	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	select {
	case <-done:
	case <-ctx.Done():
	}
}
