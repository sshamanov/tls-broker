package core

import (
	"context"
	"time"
)

// Clock is the only source of time for code that makes decisions. Production
// uses SystemClock; tests use coretest.FakeClock.
type Clock interface {
	// Now returns the current time.
	Now() time.Time
	// After returns a channel that receives the then-current time once d
	// has elapsed on this clock. d <= 0 fires immediately. The channel is
	// buffered; an abandoned channel leaks nothing that matters.
	After(d time.Duration) <-chan time.Time
}

// SystemClock is the real clock. Now is in UTC.
type SystemClock struct{}

// Now implements Clock.
func (SystemClock) Now() time.Time { return time.Now().UTC() }

// After implements Clock.
func (SystemClock) After(d time.Duration) <-chan time.Time { return time.After(d) }

// Sleep waits for d on the clock or until ctx is done. It returns nil after a
// full sleep and ctx.Err() otherwise.
func Sleep(ctx context.Context, c Clock, d time.Duration) error {
	if d <= 0 {
		return ctx.Err()
	}
	select {
	case <-c.After(d):
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
