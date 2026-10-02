package sched

import (
	"fmt"
	"slices"
	"time"

	"tls-broker/internal/core"
)

// bucketID identifies one sliding-window counter of a provider.
type bucketID struct {
	kind core.BudgetKind
	key  string
}

// event is the in-memory copy of one core.BudgetEvent.
type event struct {
	kind      core.BudgetKind
	at        time.Time
	ref       string
	renewal   bool
	committed bool
	bucket    *bucket
}

// bucket holds the events of one counter, ordered by time.
type bucket struct {
	id     bucketID
	events []*event
}

func (b *bucket) insert(e *event) {
	i := len(b.events)
	for i > 0 && b.events[i-1].at.After(e.at) {
		i--
	}
	b.events = slices.Insert(b.events, i, e)
	e.bucket = b
}

func (b *bucket) remove(e *event) {
	if i := slices.Index(b.events, e); i >= 0 {
		b.events = slices.Delete(b.events, i, i+1)
	}
	e.bucket = nil
}

// inWindow returns the times of the events that count at now (At after
// now-window), oldest first.
func (b *bucket) inWindow(window time.Duration, now time.Time) []time.Time {
	start := now.Add(-window)
	var out []time.Time
	for _, e := range b.events {
		if e.at.After(start) {
			out = append(out, e.at)
		}
	}
	return out
}

// used counts the events inside the window.
func (b *bucket) used(window time.Duration, now time.Time) int {
	if b == nil {
		return 0
	}
	return len(b.inWindow(window, now))
}

// compact drops committed events older than cutoff. Reserved events stay
// whatever their age: they belong to an open reservation.
func (b *bucket) compact(cutoff time.Time) {
	b.events = slices.DeleteFunc(b.events, func(e *event) bool {
		if e.committed && e.at.Before(cutoff) {
			e.bucket = nil
			return true
		}
		return false
	})
}

// enforced reports whether a limit is enforced at all.
func enforced(l core.Limit) bool { return l.Count > 0 && l.Window > 0 }

// threshold is the usage at which a request is refused: Count for renewals,
// Count*(100-reserve)/100 (at least 1) for everything else.
func threshold(l core.Limit, reservePercent int, renewal bool) int {
	if renewal {
		return l.Count
	}
	pct := min(max(reservePercent, 0), 90)
	t := l.Count * (100 - pct) / 100
	return max(t, 1)
}

// limitFor returns the limit of a budget kind.
func limitFor(l core.ProviderLimits, k core.BudgetKind) core.Limit {
	switch k {
	case core.BudgetNewOrder:
		return l.NewOrders
	case core.BudgetCertDomain:
		return l.CertsPerDomain
	case core.BudgetCertSet:
		return l.CertsPerSet
	}
	return core.Limit{}
}

// retention is the longest window of any configured provider: how long
// committed events must be kept to count correctly.
func retention(cfg *core.Config) time.Duration {
	var d time.Duration
	for _, p := range cfg.Providers {
		for _, l := range []core.Limit{p.Limits.NewOrders, p.Limits.CertsPerDomain, p.Limits.CertsPerSet} {
			d = max(d, l.Window)
		}
	}
	return d
}

// refusal describes one exhausted budget.
type refusal struct {
	retryAfter time.Duration
	reason     string
}

// check returns a refusal when the bucket has no room for one more event.
// The retry time is when enough counted events have left the window for the
// usage to drop below the threshold.
func check(b *bucket, id bucketID, l core.Limit, reservePercent int, renewal bool, now time.Time) *refusal {
	if !enforced(l) || b == nil {
		return nil
	}
	limit := threshold(l, reservePercent, renewal)
	ats := b.inWindow(l.Window, now)
	if len(ats) < limit {
		return nil
	}
	leaves := ats[len(ats)-limit].Add(l.Window)
	r := &refusal{retryAfter: leaves.Sub(now), reason: describe(id)}
	if !renewal && limit < l.Count {
		r.reason += fmt.Sprintf(" (last %d of %d reserved for renewals)", l.Count-limit, l.Count)
	}
	return r
}

func describe(id bucketID) string {
	switch id.kind {
	case core.BudgetNewOrder:
		return "new orders per account"
	case core.BudgetCertDomain:
		return "certificates per registered domain " + id.key
	case core.BudgetCertSet:
		return "certificates per identifier set " + id.key
	}
	return string(id.kind)
}
