package chinarules

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
)

type Compact struct {
	Source      string   `json:"source"`
	GeneratedAt string   `json:"generatedAt,omitempty"`
	Stats       any      `json:"stats,omitempty"`
	Exacts      []string `json:"exacts"`
	Suffixes    []string `json:"suffixes"`
	Keywords    []string `json:"keywords"`
	CIDRv4      []string `json:"cidr_v4"`
	CIDRv6      []string `json:"cidr_v6"`
}

type learnedEntry struct {
	ExpiresAt time.Time
}

type Store struct {
	exacts   map[string]struct{}
	suffixes map[string]struct{}
	keywords []string
	v4nets   []*net.IPNet
	v6nets   []*net.IPNet

	mu      sync.RWMutex
	learned map[string]learnedEntry
}

func Load(path string) (*Store, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read china rules: %w", err)
	}
	var c Compact
	if err := json.Unmarshal(b, &c); err != nil {
		return nil, fmt.Errorf("parse china rules: %w", err)
	}
	s := &Store{
		exacts:   make(map[string]struct{}, len(c.Exacts)),
		suffixes: make(map[string]struct{}, len(c.Suffixes)),
		learned:  map[string]learnedEntry{},
	}
	for _, v := range c.Exacts {
		v = normalize(v)
		if v != "" {
			s.exacts[v] = struct{}{}
		}
	}
	for _, v := range c.Suffixes {
		v = normalize(v)
		if v != "" {
			s.suffixes[v] = struct{}{}
		}
	}

	for _, v := range c.Keywords {
		v = strings.TrimSpace(strings.ToLower(v))
		if v != "" {
			s.keywords = append(s.keywords, v)
		}
	}
	sort.Slice(s.keywords, func(i, j int) bool { return len(s.keywords[i]) > len(s.keywords[j]) })

	for _, raw := range c.CIDRv4 {
		if _, n, err := net.ParseCIDR(strings.TrimSpace(raw)); err == nil {
			s.v4nets = append(s.v4nets, n)
		}
	}
	for _, raw := range c.CIDRv6 {
		if _, n, err := net.ParseCIDR(strings.TrimSpace(raw)); err == nil {
			s.v6nets = append(s.v6nets, n)
		}
	}
	return s, nil
}

func (s *Store) IsCNDomain(name string, now time.Time) bool {
	host := normalize(name)
	if host == "" {
		return false
	}
	if s.isLearned(host, now) {
		return true
	}
	if _, ok := s.exacts[host]; ok {
		return true
	}
	for candidate := host; candidate != ""; candidate = parentDomain(candidate) {
		if _, ok := s.suffixes[candidate]; ok {
			return true
		}
	}
	for _, kw := range s.keywords {
		if strings.Contains(host, kw) {
			return true
		}
	}
	return false
}

func (s *Store) LearnCNDomain(name string, ttl time.Duration, now time.Time) {
	host := normalize(name)
	if host == "" || ttl <= 0 {
		return
	}
	s.mu.Lock()
	s.learned[host] = learnedEntry{ExpiresAt: now.Add(ttl)}
	s.mu.Unlock()
}

func (s *Store) ShouldLearnAllAnswersCN(msgBytes []byte) bool {
	var msg dns.Msg
	if err := msg.Unpack(msgBytes); err != nil {
		return false
	}
	if msg.Rcode != dns.RcodeSuccess || len(msg.Answer) == 0 {
		return false
	}
	totalIPs := 0
	for _, rr := range msg.Answer {
		switch v := rr.(type) {
		case *dns.A:
			totalIPs++
			if !s.containsIP(v.A) {
				return false
			}
		case *dns.AAAA:
			totalIPs++
			if !s.containsIP(v.AAAA) {
				return false
			}
		}
	}
	return totalIPs > 0
}

func (s *Store) containsIP(ip net.IP) bool {
	if ip == nil {
		return false
	}
	if v4 := ip.To4(); v4 != nil {
		for _, n := range s.v4nets {
			if n.Contains(v4) {
				return true
			}
		}
		return false
	}
	for _, n := range s.v6nets {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

func (s *Store) isLearned(host string, now time.Time) bool {
	s.mu.RLock()
	entry, ok := s.learned[host]
	s.mu.RUnlock()
	if !ok {
		return false
	}
	if now.After(entry.ExpiresAt) {
		s.mu.Lock()
		delete(s.learned, host)
		s.mu.Unlock()
		return false
	}
	return true
}

func normalize(v string) string {
	return strings.Trim(strings.TrimSpace(strings.ToLower(v)), ".")
}

func parentDomain(domain string) string {
	if i := strings.IndexByte(domain, '.'); i >= 0 && i+1 < len(domain) {
		return domain[i+1:]
	}
	return ""
}
