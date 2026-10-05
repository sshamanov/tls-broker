package ctlog

import (
	"context"
	"strconv"
	"sync"

	"tls-broker/internal/names"
)

// FakeSource is an in-memory Source for tests: issuances are added per
// domain and listed with the same cursor semantics as Cert Spotter (IDs
// increase in the order of Add; a page holds at most PageSize issuances).
type FakeSource struct {
	mu       sync.Mutex
	pageSize int
	seq      int
	items    []fakeItem
	fail     map[string]error // domain -> error for the next calls
	calls    []FakeCall
}

type fakeItem struct {
	seq int
	is  Issuance
}

// FakeCall records one List call.
type FakeCall struct{ Domain, After string }

// NewFakeSource returns an empty fake with pages of pageSize (0 means 100).
func NewFakeSource(pageSize int) *FakeSource {
	if pageSize <= 0 {
		pageSize = 100
	}
	return &FakeSource{pageSize: pageSize, fail: map[string]error{}}
}

// Add publishes issuances; each gets the next ID unless it has one.
func (f *FakeSource) Add(list ...Issuance) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, is := range list {
		f.seq++
		if is.ID == "" {
			is.ID = strconv.Itoa(f.seq)
		}
		is.Names = normalizeNames(is.Names)
		f.items = append(f.items, fakeItem{seq: f.seq, is: is})
	}
}

// Fail makes List for domain return err until Fail(domain, nil).
func (f *FakeSource) Fail(domain string, err error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err == nil {
		delete(f.fail, domain)
		return
	}
	f.fail[domain] = err
}

// Calls returns the List calls so far.
func (f *FakeSource) Calls() []FakeCall {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]FakeCall(nil), f.calls...)
}

// List implements Source. An issuance matches when one of its names is the
// domain or below it (a wildcard counts as its base name).
func (f *FakeSource) List(ctx context.Context, domain, after string) ([]Issuance, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, FakeCall{domain, after})
	if err := f.fail[domain]; err != nil {
		return nil, err
	}
	start := 0
	if after != "" {
		start = -1
		for i, it := range f.items {
			if it.is.ID == after {
				start = i + 1
				break
			}
		}
		if start < 0 {
			start = len(f.items)
		}
	}
	var out []Issuance
	for _, it := range f.items[start:] {
		if len(out) == f.pageSize {
			break
		}
		for _, n := range it.is.Names {
			if names.InZone(names.Base(n), domain) {
				out = append(out, it.is)
				break
			}
		}
	}
	return out, nil
}
