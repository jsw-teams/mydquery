package cache

import (
	"container/list"
	"crypto/sha256"
	"encoding/hex"
	"sync"
	"time"
)

type Entry struct {
	Body       []byte
	ExpiresAt  time.Time
	StaleUntil time.Time
}

type Stats struct {
	Items   int    `json:"items"`
	Hits    uint64 `json:"hits"`
	Misses  uint64 `json:"misses"`
	Stales  uint64 `json:"stales"`
	Evicted uint64 `json:"evicted"`
}

type Cache struct {
	mu       sync.Mutex
	items    map[string]*list.Element
	lru      *list.List
	maxItems int
	stats    Stats
}

type node struct {
	key   string
	entry Entry
}

func New(maxItems int) *Cache {
	if maxItems <= 0 {
		maxItems = 1000
	}
	return &Cache{
		items:    make(map[string]*list.Element, maxItems),
		lru:      list.New(),
		maxItems: maxItems,
	}
}

func Key(parts ...string) string {
	h := sha256.New()
	for _, p := range parts {
		h.Write([]byte{0})
		h.Write([]byte(p))
	}
	return hex.EncodeToString(h.Sum(nil))
}

func (c *Cache) GetFresh(key string, now time.Time) ([]byte, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()

	elem, ok := c.items[key]
	if !ok {
		c.stats.Misses++
		return nil, false
	}
	item := elem.Value.(*node)
	if now.After(item.entry.ExpiresAt) {
		if now.After(item.entry.StaleUntil) {
			c.removeElement(elem)
		}
		c.stats.Misses++
		return nil, false
	}
	c.lru.MoveToFront(elem)
	c.stats.Hits++
	return clone(item.entry.Body), true
}

func (c *Cache) GetStale(key string, now time.Time) ([]byte, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()

	elem, ok := c.items[key]
	if !ok {
		c.stats.Misses++
		return nil, false
	}
	item := elem.Value.(*node)
	if now.After(item.entry.StaleUntil) {
		c.removeElement(elem)
		c.stats.Misses++
		return nil, false
	}
	c.lru.MoveToFront(elem)
	c.stats.Stales++
	return clone(item.entry.Body), true
}

func (c *Cache) Set(key string, body []byte, ttl, staleExtra time.Duration, now time.Time) {
	if ttl <= 0 {
		return
	}

	entry := Entry{
		Body:       clone(body),
		ExpiresAt:  now.Add(ttl),
		StaleUntil: now.Add(ttl),
	}
	if staleExtra > 0 {
		entry.StaleUntil = entry.StaleUntil.Add(staleExtra)
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	if elem, ok := c.items[key]; ok {
		item := elem.Value.(*node)
		item.entry = entry
		c.lru.MoveToFront(elem)
	} else {
		elem := c.lru.PushFront(&node{key: key, entry: entry})
		c.items[key] = elem
	}

	for len(c.items) > c.maxItems {
		c.removeOldest()
	}
}

func (c *Cache) Delete(key string) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if elem, ok := c.items[key]; ok {
		c.removeElement(elem)
	}
}

func (c *Cache) Stats() Stats {
	c.mu.Lock()
	defer c.mu.Unlock()

	stats := c.stats
	stats.Items = len(c.items)
	return stats
}

func (c *Cache) removeOldest() {
	elem := c.lru.Back()
	if elem == nil {
		return
	}
	c.removeElement(elem)
	c.stats.Evicted++
}

func (c *Cache) removeElement(elem *list.Element) {
	item := elem.Value.(*node)
	delete(c.items, item.key)
	c.lru.Remove(elem)
}

func clone(in []byte) []byte {
	out := make([]byte, len(in))
	copy(out, in)
	return out
}
