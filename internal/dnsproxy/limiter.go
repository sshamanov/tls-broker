package dnsproxy

import (
	"net/netip"
	"sync"
	"time"

	"tls-broker/internal/core"
)

// limiter is a sliding-window counter per source address: at most limit.Count
// admissions in any limit.Window. Count <= 0 disables it.
type limiter struct {
	limit core.Limit
	clock core.Clock

	mu   sync.Mutex
	hits map[netip.Addr][]time.Time
}

func newLimiter(l core.Limit, c core.Clock) *limiter {
	return &limiter{limit: l, clock: c, hits: map[netip.Addr][]time.Time{}}
}

// allow admits one event of src and returns true, or returns false and how
// long until the oldest event leaves the window.
func (l *limiter) allow(src netip.Addr) (bool, time.Duration) {
	if l.limit.Count <= 0 || l.limit.Window <= 0 {
		return true, 0
	}
	now := l.clock.Now()
	l.mu.Lock()
	defer l.mu.Unlock()
	h := l.prune(src, now)
	if len(h) >= l.limit.Count {
		return false, h[0].Add(l.limit.Window).Sub(now)
	}
	l.hits[src] = append(h, now)
	return true, 0
}

func (l *limiter) prune(src netip.Addr, now time.Time) []time.Time {
	h := l.hits[src]
	cut := now.Add(-l.limit.Window)
	i := 0
	for i < len(h) && !h[i].After(cut) {
		i++
	}
	h = h[i:]
	if len(h) == 0 {
		delete(l.hits, src)
	} else {
		l.hits[src] = h
	}
	return h
}

// gc drops addresses whose events have all left the window.
func (l *limiter) gc() {
	if l.limit.Count <= 0 {
		return
	}
	now := l.clock.Now()
	l.mu.Lock()
	defer l.mu.Unlock()
	for src := range l.hits {
		l.prune(src, now)
	}
}
