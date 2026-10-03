package acmesrv

import (
	"crypto/rand"
	"encoding/base64"
	"sync"
	"time"

	"tls-broker/internal/core"
)

// noncePool issues anti-replay nonces and accepts each one exactly once
// within its lifetime. It is in memory only: a restart invalidates every
// outstanding nonce, which clients handle by retrying after badNonce.
//
// Size is bounded: when more than max nonces are outstanding, the oldest are
// forgotten (a client holding one gets badNonce and retries).
type noncePool struct {
	mu    sync.Mutex
	clock core.Clock
	ttl   time.Duration
	max   int
	live  map[string]time.Time // nonce -> issued at
	queue []nonceEntry         // issue order; may hold consumed entries
}

type nonceEntry struct {
	nonce string
	at    time.Time
}

func newNoncePool(clock core.Clock, ttl time.Duration, max int) *noncePool {
	return &noncePool{clock: clock, ttl: ttl, max: max, live: map[string]time.Time{}}
}

// New returns a fresh nonce: 128 random bits, base64url without padding.
func (p *noncePool) New() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic("acmesrv: crypto/rand failed: " + err.Error())
	}
	n := base64.RawURLEncoding.EncodeToString(b[:])
	p.mu.Lock()
	defer p.mu.Unlock()
	now := p.clock.Now()
	p.live[n] = now
	p.queue = append(p.queue, nonceEntry{n, now})
	p.pruneLocked(now)
	return n
}

// Use consumes the nonce. It reports false for a nonce that was never
// issued, was already used, has expired or was evicted.
func (p *noncePool) Use(n string) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	at, ok := p.live[n]
	if !ok {
		return false
	}
	delete(p.live, n)
	return p.clock.Now().Sub(at) < p.ttl
}

// Len returns the number of outstanding nonces (for tests).
func (p *noncePool) Len() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.live)
}

func (p *noncePool) pruneLocked(now time.Time) {
	for len(p.queue) > 0 {
		head := p.queue[0]
		at, ok := p.live[head.nonce]
		current := ok && at.Equal(head.at)
		if current && now.Sub(at) < p.ttl && len(p.live) <= p.max {
			break
		}
		if current {
			delete(p.live, head.nonce)
		}
		p.queue = p.queue[1:]
	}
	// Consumed nonces leave stale queue entries behind; compact when they
	// dominate so the queue stays proportional to the live set.
	if len(p.queue) > 2*len(p.live)+1024 {
		q := make([]nonceEntry, 0, len(p.live))
		for _, e := range p.queue {
			if at, ok := p.live[e.nonce]; ok && at.Equal(e.at) {
				q = append(q, e)
			}
		}
		p.queue = q
	}
}
