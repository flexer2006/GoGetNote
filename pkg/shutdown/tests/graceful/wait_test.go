package graceful_test

import (
	"context"
	"os"
	"sync"
	"syscall"
	"testing"
	"time"

	"gogetnote/pkg/shutdown"
)

func TestWaitExecutesHooks(t *testing.T) {
	hook1Called := make(chan struct{})
	hook2Called := make(chan struct{})

	hook1 := func(ctx context.Context) error {
		close(hook1Called)
		return nil
	}

	hook2 := func(ctx context.Context) error {
		close(hook2Called)
		return nil
	}

	go func() {
		shutdown.Wait(time.Second, hook1, hook2)
	}()

	time.Sleep(100 * time.Millisecond)

	process, err := os.FindProcess(os.Getpid())
	if err != nil {
		t.Fatalf("Failed to find process: %v", err)
	}
	if err := process.Signal(syscall.SIGTERM); err != nil {
		t.Fatalf("Failed to send signal: %v", err)
	}

	select {
	case <-hook1Called:
	case <-time.After(2 * time.Second):
		t.Error("Hook 1 was not called")
	}

	select {
	case <-hook2Called:
	case <-time.After(2 * time.Second):
		t.Error("Hook 2 was not called")
	}
}

func TestWaitRespectsTimeout(t *testing.T) {
	var mu sync.Mutex
	completed := false

	waitDone := make(chan struct{})

	slowHook := func(ctx context.Context) error {
		select {
		case <-time.After(2 * time.Second):
			mu.Lock()
			completed = true
			mu.Unlock()
			return nil
		case <-ctx.Done():
			return ctx.Err()
		}
	}

	start := time.Now()
	go func() {
		shutdown.Wait(500*time.Millisecond, slowHook)
		close(waitDone)
	}()

	time.Sleep(100 * time.Millisecond)
	process, _ := os.FindProcess(os.Getpid())
	_ = process.Signal(syscall.SIGTERM)

	select {
	case <-waitDone:
	case <-time.After(3 * time.Second):
		t.Fatal("Wait function didn't return within the expected time")
	}

	elapsed := time.Since(start)
	if elapsed > 750*time.Millisecond {
		t.Errorf("Wait didn't respect timeout: took %v", elapsed)
	}

	mu.Lock()
	defer mu.Unlock()
	if completed {
		t.Error("The slow hook shouldn't have completed")
	}
}

func TestWaitRunsHooksConcurrently(t *testing.T) {
	var wg sync.WaitGroup
	wg.Add(2)

	start := time.Now()

	hook1 := func(ctx context.Context) error {
		time.Sleep(500 * time.Millisecond)
		wg.Done()
		return nil
	}

	hook2 := func(ctx context.Context) error {
		time.Sleep(500 * time.Millisecond)
		wg.Done()
		return nil
	}

	go func() {
		shutdown.Wait(time.Second, hook1, hook2)
	}()

	time.Sleep(100 * time.Millisecond)
	process, _ := os.FindProcess(os.Getpid())
	_ = process.Signal(syscall.SIGTERM)

	waitCh := make(chan struct{})
	go func() {
		wg.Wait()
		close(waitCh)
	}()

	select {
	case <-waitCh:
		elapsed := time.Since(start)
		if elapsed >= 900*time.Millisecond {
			t.Errorf("Hooks appear to run sequentially: %v", elapsed)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Timed out waiting for hooks to complete")
	}
}
