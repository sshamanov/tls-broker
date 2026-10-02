package coretest

import (
	"context"
	"fmt"
	"net/netip"
	"slices"
	"strings"
	"sync"

	"tls-broker/internal/core"
)

// FakeResolver is a core.Resolver backed by tables. Names are matched case-
// insensitively and without trailing dot. A name with no entry behaves like
// NXDOMAIN: empty result, nil error.
type FakeResolver struct {
	mu      sync.Mutex
	a       map[string][]netip.Addr
	cname   map[string]string
	txt     map[string][]string
	caa     map[string][]core.CAA
	fail    map[string]error
	failAll error
	calls   map[string]int
	// MaxCNAMEHops is the CNAME chain limit; default 8.
	MaxCNAMEHops int
}

var _ core.Resolver = (*FakeResolver)(nil)

// NewFakeResolver returns an empty resolver.
func NewFakeResolver() *FakeResolver {
	return &FakeResolver{
		a: map[string][]netip.Addr{}, cname: map[string]string{}, txt: map[string][]string{},
		caa: map[string][]core.CAA{}, fail: map[string]error{}, calls: map[string]int{}, MaxCNAMEHops: 8,
	}
}

func key(name string) string { return strings.ToLower(strings.TrimSuffix(name, ".")) }

// SetA replaces the A records of name. Addresses are IPv4 strings; it panics
// on a malformed one. No addresses removes the entry.
func (r *FakeResolver) SetA(name string, addrs ...string) {
	parsed := make([]netip.Addr, 0, len(addrs))
	for _, s := range addrs {
		parsed = append(parsed, netip.MustParseAddr(s))
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(parsed) == 0 {
		delete(r.a, key(name))
		return
	}
	r.a[key(name)] = parsed
}

// SetCNAME makes name an alias of target; an empty target removes it.
func (r *FakeResolver) SetCNAME(name, target string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if target == "" {
		delete(r.cname, key(name))
		return
	}
	r.cname[key(name)] = key(target)
}

// SetTXT replaces the TXT records of name; no values removes the entry.
func (r *FakeResolver) SetTXT(name string, values ...string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(values) == 0 {
		delete(r.txt, key(name))
		return
	}
	r.txt[key(name)] = slices.Clone(values)
}

// AddTXT adds one TXT value to name (duplicates are kept once).
func (r *FakeResolver) AddTXT(name, value string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	k := key(name)
	if !slices.Contains(r.txt[k], value) {
		r.txt[k] = append(r.txt[k], value)
	}
}

// RemoveTXT removes one TXT value from name.
func (r *FakeResolver) RemoveTXT(name, value string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	k := key(name)
	r.txt[k] = slices.DeleteFunc(r.txt[k], func(v string) bool { return v == value })
	if len(r.txt[k]) == 0 {
		delete(r.txt, k)
	}
}

// SetCAA replaces the CAA RRset at name; no records removes it.
func (r *FakeResolver) SetCAA(name string, records ...core.CAA) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(records) == 0 {
		delete(r.caa, key(name))
		return
	}
	r.caa[key(name)] = slices.Clone(records)
}

// Fail makes every lookup that starts at name return err (use
// core.ErrResolver for a resolver failure). A nil err removes the failure.
func (r *FakeResolver) Fail(name string, err error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if err == nil {
		delete(r.fail, key(name))
		return
	}
	r.fail[key(name)] = err
}

// FailAll makes every lookup return err; nil restores normal behaviour.
func (r *FakeResolver) FailAll(err error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.failAll = err
}

// Calls returns how many lookups of the kind ("A", "TXT", "CAA") were made;
// an empty kind returns the total.
func (r *FakeResolver) Calls(kind string) int {
	r.mu.Lock()
	defer r.mu.Unlock()
	if kind == "" {
		return r.calls["A"] + r.calls["TXT"] + r.calls["CAA"]
	}
	return r.calls[kind]
}

// begin counts the call and returns the injected failure, if any. The caller
// holds no lock.
func (r *FakeResolver) begin(ctx context.Context, kind, name string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	r.calls[kind]++
	if r.failAll != nil {
		return r.failAll
	}
	return r.fail[key(name)]
}

// chase follows CNAMEs from name and returns the terminal name.
func (r *FakeResolver) chase(name string) (string, error) {
	cur := key(name)
	seen := map[string]bool{cur: true}
	for hops := 0; ; hops++ {
		next, ok := r.cname[cur]
		if !ok {
			return cur, nil
		}
		if hops >= r.MaxCNAMEHops {
			return "", fmt.Errorf("%w: CNAME chain from %s is too long", core.ErrResolver, name)
		}
		if seen[next] {
			return "", fmt.Errorf("%w: CNAME loop at %s", core.ErrResolver, next)
		}
		seen[next] = true
		cur = next
	}
}

// LookupA implements core.Resolver.
func (r *FakeResolver) LookupA(ctx context.Context, name string) ([]netip.Addr, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if err := r.begin(ctx, "A", name); err != nil {
		return nil, err
	}
	end, err := r.chase(name)
	if err != nil {
		return nil, err
	}
	return slices.Clone(r.a[end]), nil
}

// LookupTXT implements core.Resolver.
func (r *FakeResolver) LookupTXT(ctx context.Context, name string) ([]string, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if err := r.begin(ctx, "TXT", name); err != nil {
		return nil, err
	}
	end, err := r.chase(name)
	if err != nil {
		return nil, err
	}
	return slices.Clone(r.txt[end]), nil
}

// LookupCAA implements core.Resolver: the RRset at that node only.
func (r *FakeResolver) LookupCAA(ctx context.Context, name string) ([]core.CAA, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if err := r.begin(ctx, "CAA", name); err != nil {
		return nil, err
	}
	end, err := r.chase(name)
	if err != nil {
		return nil, err
	}
	return slices.Clone(r.caa[end]), nil
}
