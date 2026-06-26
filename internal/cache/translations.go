package cache

import (
	"encoding/json"
	"sync"
)

type TranslationsCache struct {
	mu      sync.RWMutex
	byLang  map[string]string
	allJSON string
	loaded  bool
}

func NewTranslationsCache() *TranslationsCache {
	return &TranslationsCache{
		byLang: make(map[string]string),
	}
}

func (c *TranslationsCache) Load(translations map[string]map[string]string) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.byLang = make(map[string]string)
	for lang, data := range translations {
		if b, err := json.Marshal(data); err == nil {
			c.byLang[lang] = string(b)
		}
	}

	if b, err := json.Marshal(translations); err == nil {
		c.allJSON = string(b)
	}

	c.loaded = true
}

func (c *TranslationsCache) GetByLang(lang string) string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if v, ok := c.byLang[lang]; ok {
		return v
	}
	return c.byLang["en"]
}

func (c *TranslationsCache) GetAll() string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.allJSON
}

func (c *TranslationsCache) IsLoaded() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.loaded
}
