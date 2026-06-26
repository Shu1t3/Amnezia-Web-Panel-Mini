package cache

import (
	"sync"
	"time"
)

type WgStatsCache struct {
	mu        sync.RWMutex
	stats     map[string]map[string]interface{}
	lastFetch map[string]time.Time
	ttl       time.Duration
}

func NewWgStatsCache(ttl time.Duration) *WgStatsCache {
	return &WgStatsCache{
		stats:     make(map[string]map[string]interface{}),
		lastFetch: make(map[string]time.Time),
		ttl:       ttl,
	}
}

func (c *WgStatsCache) Get(serverID string) (map[string]interface{}, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if time.Since(c.lastFetch[serverID]) < c.ttl {
		return c.stats[serverID], true
	}
	return nil, false
}

func (c *WgStatsCache) Set(serverID string, stats map[string]interface{}) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.stats[serverID] = stats
	c.lastFetch[serverID] = time.Now()
}

func (c *WgStatsCache) Invalidate(serverID string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.stats, serverID)
	delete(c.lastFetch, serverID)
}
