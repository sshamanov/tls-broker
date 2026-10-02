package auth

import (
	"errors"
	"fmt"
	"net/netip"
	"sync"
	"time"

	"tls-broker/internal/core"
)

const (
	throttleMax    = 5
	throttleWindow = time.Minute
	// throttleSweepAt is the table size above which expired entries are
	// swept on insert.
	throttleSweepAt = 4096
)

// ThrottledError is returned by Login when too many recent failures exist for
// the username and source address. It matches core.ErrInvalidCredentials, so
// callers that only know the core errors treat it as a failed login.
type ThrottledError struct{ RetryAfter time.Duration }

func (e *ThrottledError) Error() string {
	return fmt.Sprintf("too many login attempts, retry in %s", e.RetryAfter.Round(time.Second))
}

// Is makes errors.Is(err, core.ErrInvalidCredentials) true.
func (e *ThrottledError) Is(target error) bool { return target == core.ErrInvalidCredentials }

// AsThrottled returns the *ThrottledError in err's chain, or nil.
func AsThrottled(err error) *ThrottledError {
	var t *ThrottledError
	if errors.As(err, &t) {
		return t
	}
	return nil
}

type throttleKey struct {
	user string
	ip   netip.Addr
}

// throttle keeps the failure times of the last window per username and source
// address, in memory. It is not persisted: a restart forgets it.
type throttle struct {
	mu sync.Mutex
	m  map[throttleKey][]time.Time
}

func newThrottle() *throttle { return &throttle{m: map[throttleKey][]time.Time{}} }

func (t *throttle) prune(k throttleKey, now time.Time) []time.Time {
	fails := t.m[k]
	i := 0
	for i < len(fails) && !fails[i].After(now.Add(-throttleWindow)) {
		i++
	}
	fails = fails[i:]
	if len(fails) == 0 {
		delete(t.m, k)
		return nil
	}
	t.m[k] = fails
	return fails
}

// check returns 0 when an attempt is allowed, otherwise how long until it is.
func (t *throttle) check(k throttleKey, now time.Time) time.Duration {
	t.mu.Lock()
	defer t.mu.Unlock()
	fails := t.prune(k, now)
	if len(fails) < throttleMax {
		return 0
	}
	return fails[len(fails)-throttleMax].Add(throttleWindow).Sub(now)
}

func (t *throttle) fail(k throttleKey, now time.Time) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if len(t.m) >= throttleSweepAt {
		for kk := range t.m {
			t.prune(kk, now)
		}
	}
	t.m[k] = append(t.prune(k, now), now)
}

func (t *throttle) reset(k throttleKey) {
	t.mu.Lock()
	defer t.mu.Unlock()
	delete(t.m, k)
}
