package utils

import (
	"testing"
	"time"
)

func TestCache_SetGet(t *testing.T) {
	c := NewCache[string](time.Minute)
	defer c.Stop()

	c.Set("key1", "value1")
	if v, ok := c.Get("key1"); !ok || v != "value1" {
		t.Errorf("expected 'value1', got '%s', ok=%v", v, ok)
	}
}

func TestCache_GetNonExistent(t *testing.T) {
	c := NewCache[string](time.Minute)
	defer c.Stop()

	if _, ok := c.Get("missing"); ok {
		t.Error("expected false for missing key")
	}
}

func TestCache_Expiry(t *testing.T) {
	c := NewCache[string](time.Millisecond * 10)
	defer c.Stop()

	c.Set("key1", "value1")
	time.Sleep(20 * time.Millisecond)

	if _, ok := c.Get("key1"); ok {
		t.Error("expected false for expired key")
	}
}

func TestCache_SetWithTTL(t *testing.T) {
	c := NewCache[int](time.Hour)
	defer c.Stop()

	c.SetWithTTL("short", 42, time.Millisecond*10)
	c.SetWithTTL("long", 99, time.Hour)

	time.Sleep(15 * time.Millisecond)

	if _, ok := c.Get("short"); ok {
		t.Error("expected short key to expire")
	}
	if v, ok := c.Get("long"); !ok || v != 99 {
		t.Error("expected long key to survive")
	}
}

func TestCache_Delete(t *testing.T) {
	c := NewCache[string](time.Minute)
	defer c.Stop()

	c.Set("key1", "value1")
	c.Delete("key1")
	if _, ok := c.Get("key1"); ok {
		t.Error("expected false after delete")
	}
}

func TestCache_Clear(t *testing.T) {
	c := NewCache[string](time.Minute)
	defer c.Stop()

	c.Set("key1", "value1")
	c.Set("key2", "value2")
	c.Clear()

	if c.Size() != 0 {
		t.Errorf("expected 0 after clear, got %d", c.Size())
	}
}

func TestCache_Keys(t *testing.T) {
	c := NewCache[string](time.Minute)
	defer c.Stop()

	c.Set("a", "1")
	c.Set("b", "2")
	c.Set("c", "3")

	keys := c.Keys()
	if len(keys) != 3 {
		t.Errorf("expected 3 keys, got %d", len(keys))
	}
}

func TestCache_ConcurrentAccess(t *testing.T) {
	c := NewCache[int](time.Minute)
	defer c.Stop()

	done := make(chan struct{})
	for i := 0; i < 100; i++ {
		go func(n int) {
			defer func() { done <- struct{}{} }()
			c.Set("key", n)
			c.Get("key")
		}(i)
	}

	for i := 0; i < 100; i++ {
		<-done
	}
}
