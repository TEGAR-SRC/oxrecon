package utils

import (
	"sync"
	"time"
)

type CacheEntry[T any] struct {
	Value      T
	Expiration time.Time
}

type Cache[T any] struct {
	items    map[string]*CacheEntry[T]
	mu       sync.RWMutex
	defaultTTL time.Duration
	cleanupInterval time.Duration
	stopCleanup chan struct{}
}

func NewCache[T any](ttl time.Duration) *Cache[T] {
	c := &Cache[T]{
		items:           make(map[string]*CacheEntry[T]),
		defaultTTL:      ttl,
		cleanupInterval: ttl / 2,
		stopCleanup:    make(chan struct{}),
	}
	if ttl > 0 {
		go c.cleanup()
	}
	return c
}

func (c *Cache[T]) Set(key string, value T) {
	c.SetWithTTL(key, value, c.defaultTTL)
}

func (c *Cache[T]) SetWithTTL(key string, value T, ttl time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.items[key] = &CacheEntry[T]{
		Value:      value,
		Expiration: time.Now().Add(ttl),
	}
}

func (c *Cache[T]) Get(key string) (T, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	entry, exists := c.items[key]
	if !exists {
		var zero T
		return zero, false
	}

	if time.Now().After(entry.Expiration) {
		var zero T
		return zero, false
	}

	return entry.Value, true
}

func (c *Cache[T]) Delete(key string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.items, key)
}

func (c *Cache[T]) Clear() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.items = make(map[string]*CacheEntry[T])
}

func (c *Cache[T]) Size() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.items)
}

func (c *Cache[T]) Keys() []string {
	c.mu.RLock()
	defer c.mu.RUnlock()

	keys := make([]string, 0, len(c.items))
	now := time.Now()

	for k, v := range c.items {
		if now.Before(v.Expiration) {
			keys = append(keys, k)
		}
	}
	return keys
}

func (c *Cache[T]) cleanup() {
	ticker := time.NewTicker(c.cleanupInterval)
	defer ticker.Stop()

	for {
		select {
		case <-c.stopCleanup:
			return
		case <-ticker.C:
			c.mu.Lock()
			now := time.Now()
			for k, v := range c.items {
				if now.After(v.Expiration) {
					delete(c.items, k)
				}
			}
			c.mu.Unlock()
		}
	}
}

func (c *Cache[T]) Stop() {
	close(c.stopCleanup)
}

