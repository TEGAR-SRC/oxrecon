package utils

import (
	"context"
	"testing"
	"time"
)

func TestRateLimiter_Allow(t *testing.T) {
	rl := NewRateLimiter(100, 10)
	defer rl.Stop()

	// Should allow burst
	for i := 0; i < 10; i++ {
		if !rl.Allow() {
			t.Errorf("expected true for burst %d", i)
		}
	}
}

func TestRateLimiter_BurstExceeded(t *testing.T) {
	rl := NewRateLimiter(1, 3)
	defer rl.Stop()

	// Fill burst
	rl.Allow()
	rl.Allow()
	rl.Allow()

	// Should fail after burst
	if rl.Allow() {
		t.Error("expected false after burst exhausted")
	}
}

func TestRateLimiter_Wait(t *testing.T) {
	rl := NewRateLimiter(1000, 10)
	defer rl.Stop()

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	err := rl.Wait(ctx)
	if err != nil {
		t.Fatalf("expected nil, got %v", err)
	}
}

func TestRateLimiter_WaitCancel(t *testing.T) {
	rl := NewRateLimiter(1, 1)
	defer rl.Stop()

	// Drain the burst
	rl.Allow()

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	err := rl.Wait(ctx)
	if err == nil {
		t.Fatal("expected context error")
	}
}

func TestSlidingWindowLimiter(t *testing.T) {
	swl := NewSlidingWindowLimiter(3, time.Second)

	if !swl.Allow() {
		t.Error("expected true")
	}
	if !swl.Allow() {
		t.Error("expected true")
	}
	if !swl.Allow() {
		t.Error("expected true")
	}
	if swl.Allow() {
		t.Error("expected false at rate limit")
	}
}

func TestSlidingWindowLimiter_WindowReset(t *testing.T) {
	swl := NewSlidingWindowLimiter(2, 10*time.Millisecond)

	swl.Allow()
	swl.Allow()

	time.Sleep(15 * time.Millisecond)

	if !swl.Allow() {
		t.Error("expected true after window reset")
	}
}
