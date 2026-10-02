package coretest

import (
	"sort"
	"sync"
	"time"

	"tls-broker/internal/core"
)

// FakeClock is a core.Clock that only moves when the test moves it.
//
// Timers created with After fire during Advance/Set, in deadline order (ties
// in creation order). The clock reads exactly the timer's deadline while that
// timer fires, and the value sent on the channel is that deadline. Sends
// never block (channels are buffered), so Advance returns without waiting for
// any goroutine; use BlockUntil to wait until the code under test has
// actually armed its timer before advancing.
type FakeClock struct {
	mu     sync.Mutex
	cond   *sync.Cond
	now    time.Time
	seq    int
	timers []*fakeTimer
}

type fakeTimer struct {
	at  time.Time
	seq int
	ch  chan time.Time
}

var _ core.Clock = (*FakeClock)(nil)

// NewFakeClock returns a clock set to start, or to 2026-01-01 12:00:00 UTC
// when start is omitted.
func NewFakeClock(start ...time.Time) *FakeClock {
	c := &FakeClock{now: time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)}
	if len(start) > 0 {
		c.now = start[0]
	}
	c.cond = sync.NewCond(&c.mu)
	return c
}

// Now implements core.Clock.
func (c *FakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

// After implements core.Clock. d <= 0 fires immediately.
func (c *FakeClock) After(d time.Duration) <-chan time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	ch := make(chan time.Time, 1)
	if d <= 0 {
		ch <- c.now
		return ch
	}
	c.seq++
	c.timers = append(c.timers, &fakeTimer{at: c.now.Add(d), seq: c.seq, ch: ch})
	c.cond.Broadcast()
	return ch
}

// Advance moves the clock forward by d, firing every timer that becomes due.
func (c *FakeClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.advanceTo(c.now.Add(d))
}

// Set moves the clock to t, firing every timer that becomes due. Moving
// backwards changes Now and fires nothing.
func (c *FakeClock) Set(t time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.advanceTo(t)
}

func (c *FakeClock) advanceTo(target time.Time) {
	sort.SliceStable(c.timers, func(i, j int) bool {
		if !c.timers[i].at.Equal(c.timers[j].at) {
			return c.timers[i].at.Before(c.timers[j].at)
		}
		return c.timers[i].seq < c.timers[j].seq
	})
	n := 0
	for _, t := range c.timers {
		if t.at.After(target) {
			break
		}
		c.now = t.at
		t.ch <- t.at
		n++
	}
	c.timers = c.timers[n:]
	c.now = target
}

// Pending returns the number of timers that have not fired.
func (c *FakeClock) Pending() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.timers)
}

// BlockUntil waits (in real time) until at least n timers are pending and
// reports whether that happened within the real-time timeout. Typical use:
//
//	go codeUnderTest()            // will call clock.After(...)
//	if !clock.BlockUntil(1, time.Second) { t.Fatal("timer never armed") }
//	clock.Advance(30 * time.Second)
func (c *FakeClock) BlockUntil(n int, timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	stop := time.AfterFunc(timeout, func() {
		c.mu.Lock()
		c.cond.Broadcast()
		c.mu.Unlock()
	})
	defer stop.Stop()
	c.mu.Lock()
	defer c.mu.Unlock()
	for len(c.timers) < n {
		if !time.Now().Before(deadline) {
			return false
		}
		c.cond.Wait()
	}
	return true
}
