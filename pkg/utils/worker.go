package utils

import (
	"context"
	"sync"
	"sync/atomic"
	"time"
)

type Job func(ctx context.Context) error

type JobWithResult[T any] func(ctx context.Context) (T, error)

type WorkerPool struct {
	workers     int
	jobQueue    chan Job
	resultQueue chan error
	wg          sync.WaitGroup
	ctx         context.Context
	cancel      context.CancelFunc
	running     atomic.Bool
	metrics     WorkerMetrics
	mu          sync.RWMutex
}

type WorkerMetrics struct {
	JobsProcessed atomic.Int64
	JobsFailed    atomic.Int64
	ActiveWorkers atomic.Int64
}

func NewWorkerPool(workers int, queueSize int) *WorkerPool {
	ctx, cancel := context.WithCancel(context.Background())
	return &WorkerPool{
		workers:     workers,
		jobQueue:    make(chan Job, queueSize),
		resultQueue: make(chan error, queueSize),
		ctx:         ctx,
		cancel:      cancel,
	}
}

func (wp *WorkerPool) Start() {
	if wp.running.Load() {
		return
	}
	wp.running.Store(true)

	for i := 0; i < wp.workers; i++ {
		wp.wg.Add(1)
		go wp.worker()
	}
}

func (wp *WorkerPool) worker() {
	defer wp.wg.Done()
	wp.metrics.ActiveWorkers.Add(1)
	defer wp.metrics.ActiveWorkers.Add(-1)

	for {
		select {
		case <-wp.ctx.Done():
			return
		case job, ok := <-wp.jobQueue:
			if !ok {
				return
			}
			if err := job(wp.ctx); err != nil {
				wp.metrics.JobsFailed.Add(1)
				wp.resultQueue <- err
			} else {
				wp.metrics.JobsProcessed.Add(1)
				wp.resultQueue <- nil
			}
		}
	}
}

func (wp *WorkerPool) Submit(job Job) bool {
	if !wp.running.Load() {
		return false
	}
	select {
	case wp.jobQueue <- job:
		return true
	default:
		return false
	}
}

func (wp *WorkerPool) SubmitWithRetry(job Job, maxRetries int, backoff time.Duration) error {
	var lastErr error
	for i := 0; i <= maxRetries; i++ {
		if err := job(wp.ctx); err != nil {
			lastErr = err
			if i < maxRetries {
				select {
				case <-wp.ctx.Done():
					return wp.ctx.Err()
				case <-time.After(backoff * time.Duration(i+1)):
				}
			}
		} else {
			return nil
		}
	}
	return lastErr
}

func (wp *WorkerPool) Shutdown() {
	if !wp.running.Load() {
		return
	}
	wp.running.Store(false)
	wp.cancel()
	close(wp.jobQueue)
}

func (wp *WorkerPool) ShutdownWait() {
	wp.Shutdown()
	wp.wg.Wait()
	close(wp.resultQueue)
}

func (wp *WorkerPool) Metrics() WorkerMetrics {
	return wp.metrics
}

func (wp *WorkerPool) QueueLen() int {
	return len(wp.jobQueue)
}

func (wp *WorkerPool) IsRunning() bool {
	return wp.running.Load()
}