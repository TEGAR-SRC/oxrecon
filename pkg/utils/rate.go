package utils

import (
	"context"
	"sync"
	"time"
)

type RateLimiter struct {
	rate        int
	burst       int
	tokens      float64
	lastTick    time.Time
	mu          sync.Mutex
	ctx         context.Context
	cancel      context.CancelFunc
}

func NewRateLimiter(rate int, burst int) *RateLimiter {
	ctx, cancel := context.WithCancel(context.Background())
	rl := &RateLimiter{
		rate:     rate,
		burst:    burst,
		tokens:   float64(burst),
		lastTick: time.Now(),
		ctx:      ctx,
		cancel:   cancel,
	}
	go rl.refillLoop()
	return rl
}

func (rl *RateLimiter) refillLoop() {
	ticker := time.NewTicker(time.Second / time.Duration(rl.rate))
	defer ticker.Stop()

	for {
		select {
		case <-rl.ctx.Done():
			return
		case <-ticker.C:
			rl.mu.Lock()
			rl.tokens = float64(rl.burst)
			rl.lastTick = time.Now()
			rl.mu.Unlock()
		}
	}
}

func (rl *RateLimiter) Allow() bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	if rl.tokens > 0 {
		rl.tokens--
		return true
	}
	return false
}

func (rl *RateLimiter) Wait(ctx context.Context) error {
	for {
		rl.mu.Lock()
		if rl.tokens > 0 {
			rl.tokens--
			rl.mu.Unlock()
			return nil
		}
		rl.mu.Unlock()

		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-rl.ctx.Done():
			return rl.ctx.Err()
		case <-time.After(time.Second / time.Duration(rl.rate)):
		}
	}
}

func (rl *RateLimiter) WaitN(ctx context.Context, n int) error {
	for i := 0; i < n; i++ {
		if err := rl.Wait(ctx); err != nil {
			return err
		}
	}
	return nil
}

func (rl *RateLimiter) Stop() {
	rl.cancel()
}

type SlidingWindowLimiter struct {
	rate     int
	window   time.Duration
	requests []time.Time
	mu       sync.Mutex
}

func NewSlidingWindowLimiter(rate int, window time.Duration) *SlidingWindowLimiter {
	return &SlidingWindowLimiter{
		rate:   rate,
		window: window,
	}
}

func (swl *SlidingWindowLimiter) Allow() bool {
	swl.mu.Lock()
	defer swl.mu.Unlock()

	now := time.Now()
	cutoff := now.Add(-swl.window)

	var valid []time.Time
	for _, t := range swl.requests {
		if t.After(cutoff) {
			valid = append(valid, t)
		}
	}
	swl.requests = valid

	if len(swl.requests) < swl.rate {
		swl.requests = append(swl.requests, now)
		return true
	}
	return false
}

func (swl *SlidingWindowLimiter) Wait(ctx context.Context) error {
	for {
		if swl.Allow() {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(time.Millisecond * 100):
		}
	}
}
