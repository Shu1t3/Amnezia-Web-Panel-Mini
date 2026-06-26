package cache

import (
	"sync"
	"time"
)

type SettingsCache struct {
	mu      sync.RWMutex
	data    map[string]string
	expires time.Time
	ttl     time.Duration
}

func NewSettingsCache(ttl time.Duration) *SettingsCache {
	return &SettingsCache{
		data: make(map[string]string),
		ttl:  ttl,
	}
}

func (c *SettingsCache) Get(key string) (string, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if time.Now().After(c.expires) {
		return "", false
	}
	v, ok := c.data[key]
	return v, ok
}

func (c *SettingsCache) Set(key, value string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if time.Now().After(c.expires) {
		c.data = make(map[string]string)
	}
	c.data[key] = value
	c.expires = time.Now().Add(c.ttl)
}

func (c *SettingsCache) SetMulti(items map[string]string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.data == nil {
		c.data = make(map[string]string)
	}
	for k, v := range items {
		c.data[k] = v
	}
	c.expires = time.Now().Add(c.ttl)
}

func (c *SettingsCache) Invalidate() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.data = make(map[string]string)
	c.expires = time.Time{}
}
