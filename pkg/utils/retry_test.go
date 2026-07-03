package utils

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestRetry_Success(t *testing.T) {
	attempts := 0
	err := Retry(context.Background(), DefaultRetryConfig, func() error {
		attempts++
		if attempts < 3 {
			return errors.New("not yet")
		}
		return nil
	})

	if err != nil {
		t.Fatalf("expected nil, got %v", err)
	}
	if attempts != 3 {
		t.Errorf("expected 3 attempts, got %d", attempts)
	}
}

func TestRetry_Exhausted(t *testing.T) {
	attempts := 0
	err := Retry(context.Background(), RetryConfig{
		MaxAttempts: 2,
		InitialWait: time.Millisecond,
	}, func() error {
		attempts++
		return errors.New("always fail")
	})

	if err == nil {
		t.Fatal("expected error")
	}
	if attempts != 3 {
		t.Errorf("expected 3 attempts, got %d", attempts)
	}
}

func TestRetry_ContextCancelled(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	attempts := 0
	err := Retry(ctx, RetryConfig{
		MaxAttempts: 100,
		InitialWait: 100 * time.Millisecond,
	}, func() error {
		attempts++
		return errors.New("fail")
	})

	if err == nil {
		t.Fatal("expected context error")
	}
}

func TestRetryWithResult_Success(t *testing.T) {
	attempts := 0
	result, err := RetryWithResult(context.Background(), DefaultRetryConfig, func() (string, error) {
		attempts++
		if attempts < 2 {
			return "", errors.New("not yet")
		}
		return "success", nil
	})

	if err != nil {
		t.Fatalf("expected nil, got %v", err)
	}
	if result != "success" {
		t.Errorf("expected 'success', got '%s'", result)
	}
}

func TestRetryWithResult_Exhausted(t *testing.T) {
	attempts := 0
	result, err := RetryWithResult(context.Background(), RetryConfig{
		MaxAttempts: 2,
		InitialWait: time.Millisecond,
	}, func() (int, error) {
		attempts++
		return 0, errors.New("always fail")
	})

	if err == nil {
		t.Fatal("expected error")
	}
	if result != 0 {
		t.Errorf("expected 0, got %d", result)
	}
}

func TestDoRetry(t *testing.T) {
	attempts := 0
	err := DoRetry(func() error {
		attempts++
		if attempts < 2 {
			return errors.New("retry")
		}
		return nil
	}, DefaultRetryConfig)

	if err != nil {
		t.Fatalf("expected nil, got %v", err)
	}
}
