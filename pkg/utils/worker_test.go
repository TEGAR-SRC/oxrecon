package utils

import (
	"context"
	"sync/atomic"
	"testing"
	"time"
)

func TestWorkerPool_StartStop(t *testing.T) {
	wp := NewWorkerPool(2, 10)
	wp.Start()

	if !wp.IsRunning() {
		t.Fatal("expected worker pool to be running")
	}

	wp.Shutdown()
	if wp.IsRunning() {
		t.Fatal("expected worker pool to be stopped")
	}
}

func TestWorkerPool_Submit(t *testing.T) {
	wp := NewWorkerPool(2, 10)
	wp.Start()

	var count atomic.Int32
	done := make(chan struct{})

	go func() {
		for range wp.resultQueue {
			count.Add(1)
			if count.Load() >= 5 {
				close(done)
				return
			}
		}
	}()

	for i := 0; i < 5; i++ {
		wp.Submit(func(ctx context.Context) error {
			return nil
		})
	}

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for jobs")
	}

	wp.ShutdownWait()

	if count.Load() != 5 {
		t.Errorf("expected 5 jobs, got %d", count.Load())
	}
}

func TestWorkerPool_SubmitWithRetry(t *testing.T) {
	wp := NewWorkerPool(1, 10)
	wp.Start()

	var attempts atomic.Int32
	job := func(ctx context.Context) error {
		a := attempts.Add(1)
		if a < 3 {
			return context.Canceled
		}
		return nil
	}

	err := wp.SubmitWithRetry(job, 3, time.Millisecond)
	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}

	if attempts.Load() != 3 {
		t.Errorf("expected 3 attempts, got %d", attempts.Load())
	}

	wp.Shutdown()
}

func TestWorkerPool_Metrics(t *testing.T) {
	wp := NewWorkerPool(2, 10)
	wp.Start()

	for i := 0; i < 3; i++ {
		wp.Submit(func(ctx context.Context) error { return nil })
	}

	// Wait for jobs to process
	time.Sleep(100 * time.Millisecond)
	metrics := wp.Metrics()

	if metrics.JobsProcessed.Load() < 1 {
		t.Errorf("expected at least 1 job processed")
	}

	wp.Shutdown()
}

func TestWorkerPool_SubmitToStoppedPool(t *testing.T) {
	wp := NewWorkerPool(2, 10)
	// Don't start

	if wp.Submit(func(ctx context.Context) error { return nil }) {
		t.Error("expected false when submitting to stopped pool")
	}
}
