package cache

import (
	"sync"
	"time"
)

type ClientCache struct {
	mu        sync.RWMutex
	clients   map[string][]map[string]interface{}
	lastFetch map[string]time.Time
	ttl       time.Duration
}

func NewClientCache(ttl time.Duration) *ClientCache {
	return &ClientCache{
		clients:   make(map[string][]map[string]interface{}),
		lastFetch: make(map[string]time.Time),
		ttl:       ttl,
	}
}

func (c *ClientCache) Get(serverID string) ([]map[string]interface{}, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if time.Since(c.lastFetch[serverID]) < c.ttl {
		return c.clients[serverID], true
	}
	return nil, false
}

func (c *ClientCache) Set(serverID string, clients []map[string]interface{}) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.clients[serverID] = clients
	c.lastFetch[serverID] = time.Now()
}

func (c *ClientCache) Invalidate(serverID string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.clients, serverID)
	delete(c.lastFetch, serverID)
}

func (c *ClientCache) InvalidateAll() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.clients = make(map[string][]map[string]interface{})
	c.lastFetch = make(map[string]time.Time)
}
