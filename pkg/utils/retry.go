package utils

import (
	"context"
	"time"
)

type RetryConfig struct {
	MaxAttempts int
	InitialWait time.Duration
	MaxWait     time.Duration
	Multiplier  float64
}

var DefaultRetryConfig = RetryConfig{
	MaxAttempts: 3,
	InitialWait: time.Second,
	MaxWait:     time.Minute,
	Multiplier:  2.0,
}

func Retry(ctx context.Context, config RetryConfig, fn func() error) error {
	var err error
	wait := config.InitialWait

	for attempt := 0; attempt <= config.MaxAttempts; attempt++ {
		if attempt > 0 {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(wait):
			}
			wait = time.Duration(float64(wait) * config.Multiplier)
			if wait > config.MaxWait {
				wait = config.MaxWait
			}
		}

		if err = fn(); err == nil {
			return nil
		}
	}

	return err
}

func RetryWithResult[T any](ctx context.Context, config RetryConfig, fn func() (T, error)) (T, error) {
	var result T
	var err error
	wait := config.InitialWait

	for attempt := 0; attempt <= config.MaxAttempts; attempt++ {
		if attempt > 0 {
			select {
			case <-ctx.Done():
				return result, ctx.Err()
			case <-time.After(wait):
			}
			wait = time.Duration(float64(wait) * config.Multiplier)
			if wait > config.MaxWait {
				wait = config.MaxWait
			}
		}

		result, err = fn()
		if err == nil {
			return result, nil
		}
	}

	return result, err
}

type RetryableFunc func() error

func DoRetry(retryable RetryableFunc, config RetryConfig) error {
	return Retry(context.Background(), config, retryable)
}