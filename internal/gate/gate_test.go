package gate

import (
	"cmp"
	"context"
	"errors"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"testing"

	"tls-broker/internal/core"
	"tls-broker/internal/core/coretest"
	"tls-broker/internal/names"
)

// memGrants is an in-memory core.GrantStore following the store contract.
type memGrants struct {
	mu   sync.Mutex
	list []core.Grant
	next int64
	err  error // returned by Match when set
}

func (m *memGrants) Create(_ context.Context, g *core.Grant) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.next++
	g.ID = m.next
	g.Prefix = g.Prefix.Masked()
	m.list = append(m.list, *g)
	return nil
}

func (m *memGrants) Get(_ context.Context, id int64) (*core.Grant, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, g := range m.list {
		if g.ID == id {
			return &g, nil
		}
	}
	return nil, core.ErrNotFound
}

func (m *memGrants) List(_ context.Context, owner int64) ([]core.Grant, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []core.Grant
	for _, g := range m.list {
		if owner == 0 || g.OwnerUserID == owner {
			out = append(out, g)
		}
	}
	return out, nil
}

func (m *memGrants) Update(_ context.Context, g *core.Grant) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for i := range m.list {
		if m.list[i].ID == g.ID {
			m.list[i].Enabled, m.list[i].Wildcard, m.list[i].Note, m.list[i].OwnerUserID = g.Enabled, g.Wildcard, g.Note, g.OwnerUserID
			return nil
		}
	}
	return core.ErrNotFound
}

func (m *memGrants) Delete(_ context.Context, id int64) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for i := range m.list {
		if m.list[i].ID == id {
			m.list = slices.Delete(m.list, i, i+1)
			return nil
		}
	}
	return core.ErrNotFound
}

func (m *memGrants) Match(_ context.Context, addr netip.Addr) ([]core.Grant, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.err != nil {
		return nil, m.err
	}
	var out []core.Grant
	if !addr.Is4() {
		return out, nil
	}
	for _, g := range m.list {
		if g.Enabled && g.Prefix.Contains(addr) {
			out = append(out, g)
		}
	}
	slices.SortFunc(out, func(a, b core.Grant) int {
		if a.Wildcard != b.Wildcard {
			if a.Wildcard {
				return -1
			}
			return 1
		}
		if c := cmp.Compare(b.Prefix.Bits(), a.Prefix.Bits()); c != 0 {
			return c
		}
		return cmp.Compare(a.ID, b.ID)
	})
	return out, nil
}

const (
	srcIP       = "192.0.2.10"
	primaryAcct = "https://primary.test/acme/acct/1"
	fallbackAcc = "https://fallback.test/acme/acct/1"
	// Accounts of the operator's own ACME clients at the primary.
	operatorA = "https://primary.test/acme/acct/111111111"
	operatorB = "https://primary.test/acme/acct/222222222"
)

type env struct {
	gate      *Gate
	cfg       *coretest.FakeConfig
	res       *coretest.FakeResolver
	grants    *memGrants
	primary   *coretest.FakeCA
	fallback  *coretest.FakeCA
	providers *coretest.FakeProviders
}

func newEnv() *env {
	clk := coretest.NewFakeClock()
	e := &env{
		res:      coretest.NewFakeResolver(),
		grants:   &memGrants{},
		primary:  coretest.NewFakeCA("primary", clk),
		fallback: coretest.NewFakeCA("fallback", clk),
		cfg:      coretest.NewFakeConfig(nil),
	}
	e.providers = coretest.NewFakeProviders(e.primary, e.fallback)
	e.gate = New(e.cfg, e.grants, e.res, e.providers)
	return e
}

// trust sets the trusted accounts of a managed zone of the fixture.
func (e *env) trust(zone string, accounts ...string) {
	e.cfg.Update(func(c *core.Config) {
		for i := range c.Zones {
			if c.Zones[i].Name == zone {
				c.Zones[i].TrustedAccounts = accounts
			}
		}
	})
}

// grant creates a grant; IDs are assigned 1, 2, ... in call order.
func (e *env) grant(prefix string, enabled, wildcard bool) {
	g := &core.Grant{OwnerUserID: 7, Prefix: netip.MustParsePrefix(prefix), Enabled: enabled, Wildcard: wildcard}
	_ = e.grants.Create(context.Background(), g)
}

func issue(v string) core.CAA     { return core.CAA{Tag: "issue", Value: v} }
func issuewild(v string) core.CAA { return core.CAA{Tag: "issuewild", Value: v} }

func pinned(issuer, acct string) string { return issuer + "; accounturi=" + acct }

type authCase struct {
	name     string
	mode     core.Mode // default acme
	src      string    // default srcIP
	names    []string
	setup    func(e *env)
	allowed  bool
	reason   string
	grantID  int64
	denyName string
	detail   string // substring of Detail, when set
	aCalls   *int   // expected A lookups; nil = do not check
	caaCalls *int   // expected CAA lookups; nil = do not check
}

func n(i int) *int { return &i }

func runAuth(t *testing.T, tests []authCase) {
	t.Helper()
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			e := newEnv()
			if tc.setup != nil {
				tc.setup(e)
			}
			mode := cmp.Or(tc.mode, core.ModeACME)
			var src netip.Addr
			if tc.src != "none" {
				src = netip.MustParseAddr(cmp.Or(tc.src, srcIP))
			}
			var set names.Set
			if len(tc.names) > 0 {
				set = names.MustSet(tc.names...)
			}
			d, err := e.gate.Authorize(context.Background(), mode, src, set)
			if err != nil {
				t.Fatalf("Authorize error: %v", err)
			}
			if d.Allowed != tc.allowed || d.Reason != tc.reason || d.GrantID != tc.grantID || d.Name != tc.denyName {
				t.Fatalf("decision = %+v; want allowed=%v reason=%s grant=%d name=%q",
					d, tc.allowed, tc.reason, tc.grantID, tc.denyName)
			}
			if tc.detail != "" && !strings.Contains(d.Detail, tc.detail) {
				t.Fatalf("detail %q does not contain %q", d.Detail, tc.detail)
			}
			if tc.aCalls != nil && e.res.Calls("A") != *tc.aCalls {
				t.Fatalf("A lookups = %d, want %d", e.res.Calls("A"), *tc.aCalls)
			}
			if tc.mode != core.ModeDNSProxy && e.res.Calls("CAA") != 0 {
				t.Fatalf("CAA looked up in mode %s", mode)
			}
			if tc.caaCalls != nil && e.res.Calls("CAA") != *tc.caaCalls {
				t.Fatalf("CAA lookups = %d, want %d", e.res.Calls("CAA"), *tc.caaCalls)
			}
		})
	}
}

func TestAuthorize(t *testing.T) {
	pointHere := func(names ...string) func(e *env) {
		return func(e *env) {
			for _, n := range names {
				e.res.SetA(n, srcIP)
			}
		}
	}
	runAuth(t, []authCase{
		// Source and names.
		{name: "IPv6 source", src: "2001:db8::1", names: []string{"a.example.com"},
			reason: core.ReasonNotIPv4},
		{name: "no source", src: "none", names: []string{"a.example.com"},
			reason: core.ReasonNotIPv4},
		{name: "IPv4-mapped source is IPv4", src: "::ffff:" + srcIP, names: []string{"a.example.com"},
			setup: pointHere("a.example.com"), allowed: true, reason: core.ReasonDNSIPMatch, aCalls: n(1)},
		{name: "empty set", reason: core.ReasonInvalidIdentifier},
		{name: "outside managed zone", names: []string{"a.example.net"}, setup: pointHere("a.example.net"),
			reason: core.ReasonOutsideManagedZone, denyName: "a.example.net"},
		{name: "one name outside, even with a wildcard grant", names: []string{"a.example.com", "b.example.net"},
			setup:  func(e *env) { e.grant(srcIP+"/32", true, true) },
			reason: core.ReasonOutsideManagedZone, denyName: "b.example.net"},
		{name: "second managed zone", names: []string{"a.example.org"}, setup: pointHere("a.example.org"),
			allowed: true, reason: core.ReasonDNSIPMatch, aCalls: n(1)},

		// Grants.
		{name: "grant beats DNS, no lookup", names: []string{"a.example.com", "b.example.com"},
			setup: func(e *env) {
				e.grant(srcIP+"/32", true, false)
				e.res.SetA("a.example.com", "198.51.100.1")
			},
			allowed: true, reason: core.ReasonIPGrant, grantID: 1, aCalls: n(0)},
		{name: "disabled grant ignored, DNS decides", names: []string{"a.example.com"},
			setup: func(e *env) {
				e.grant(srcIP+"/32", false, true)
				e.res.SetA("a.example.com", srcIP)
			},
			allowed: true, reason: core.ReasonDNSIPMatch, aCalls: n(1)},
		{name: "disabled grant ignored, DNS denies", names: []string{"a.example.com"},
			setup:  func(e *env) { e.grant(srcIP+"/32", false, false) },
			reason: core.ReasonDNSMismatch, denyName: "a.example.com", detail: "no A records", aCalls: n(1)},
		{name: "CIDR first address", src: "192.0.2.0", names: []string{"a.example.com"},
			setup:   func(e *env) { e.grant("192.0.2.0/28", true, false) },
			allowed: true, reason: core.ReasonIPGrant, grantID: 1, aCalls: n(0)},
		{name: "CIDR last address", src: "192.0.2.15", names: []string{"a.example.com"},
			setup:   func(e *env) { e.grant("192.0.2.0/28", true, false) },
			allowed: true, reason: core.ReasonIPGrant, grantID: 1, aCalls: n(0)},
		{name: "CIDR just outside", src: "192.0.2.16", names: []string{"a.example.com"},
			setup:  func(e *env) { e.grant("192.0.2.0/28", true, false) },
			reason: core.ReasonDNSMismatch, denyName: "a.example.com", aCalls: n(1)},
		{name: "most specific ordinary grant", names: []string{"a.example.com"},
			setup: func(e *env) {
				e.grant("192.0.2.0/24", true, false)
				e.grant(srcIP+"/32", true, false)
				e.grant("192.0.0.0/16", true, false)
			},
			allowed: true, reason: core.ReasonIPGrant, grantID: 2, aCalls: n(0)},
		{name: "wildcard grant preferred", names: []string{"a.example.com"},
			setup: func(e *env) {
				e.grant(srcIP+"/32", true, false)
				e.grant("192.0.0.0/16", true, true)
			},
			allowed: true, reason: core.ReasonIPGrant, grantID: 2, aCalls: n(0)},

		// Wildcards.
		{name: "wildcard without any grant", names: []string{"*.example.com"},
			reason: core.ReasonWildcardGrantRequired, denyName: "*.example.com", aCalls: n(0)},
		{name: "wildcard without grant even when base resolves here", names: []string{"*.example.com", "example.com"},
			setup:  pointHere("example.com"),
			reason: core.ReasonWildcardGrantRequired, denyName: "*.example.com", aCalls: n(0)},
		{name: "wildcard with ordinary grant", names: []string{"*.example.com"},
			setup:  func(e *env) { e.grant(srcIP+"/32", true, false) },
			reason: core.ReasonWildcardGrantRequired, denyName: "*.example.com", detail: "grant 1", aCalls: n(0)},
		{name: "wildcard with disabled wildcard grant", names: []string{"*.example.com"},
			setup:  func(e *env) { e.grant(srcIP+"/32", false, true) },
			reason: core.ReasonWildcardGrantRequired, denyName: "*.example.com", aCalls: n(0)},
		{name: "wildcard grant", names: []string{"*.example.com", "example.com"},
			setup:   func(e *env) { e.grant("192.0.2.0/24", true, true) },
			allowed: true, reason: core.ReasonIPGrant, grantID: 1, aCalls: n(0)},
		{name: "wildcard grant of a blocked or deleted owner still works", names: []string{"*.example.com"},
			setup: func(e *env) {
				// The gate has no user store at all: the owner cannot matter.
				_ = e.grants.Create(context.Background(), &core.Grant{OwnerUserID: 999,
					Prefix: netip.MustParsePrefix(srcIP + "/32"), Enabled: true, Wildcard: true})
			},
			allowed: true, reason: core.ReasonIPGrant, grantID: 1, aCalls: n(0)},

		// DNS gate.
		{name: "single name resolves here", names: []string{"a.example.com"}, setup: pointHere("a.example.com"),
			allowed: true, reason: core.ReasonDNSIPMatch, aCalls: n(1)},
		{name: "multi-SAN all resolve here", names: []string{"a.example.com", "b.example.com", "c.example.org"},
			setup:   pointHere("a.example.com", "b.example.com", "c.example.org"),
			allowed: true, reason: core.ReasonDNSIPMatch, aCalls: n(3)},
		{name: "multi-SAN partial mismatch", names: []string{"a.example.com", "b.example.com"},
			setup: func(e *env) {
				e.res.SetA("a.example.com", srcIP)
				e.res.SetA("b.example.com", "198.51.100.7")
			},
			reason: core.ReasonDNSMismatch, denyName: "b.example.com", detail: "198.51.100.7", aCalls: n(2)},
		{name: "one of several A records matches", names: []string{"a.example.com"},
			setup:   func(e *env) { e.res.SetA("a.example.com", "198.51.100.1", srcIP, "198.51.100.2") },
			allowed: true, reason: core.ReasonDNSIPMatch, aCalls: n(1)},
		{name: "CNAME to a name that resolves here", names: []string{"www.example.com"},
			setup: func(e *env) {
				e.res.SetCNAME("www.example.com", "lb.example.net")
				e.res.SetA("lb.example.net", srcIP)
			},
			allowed: true, reason: core.ReasonDNSIPMatch, aCalls: n(1)},
		{name: "DNS failure", names: []string{"a.example.com", "b.example.com"},
			setup: func(e *env) {
				e.res.SetA("a.example.com", srcIP)
				e.res.Fail("b.example.com", core.ErrResolver)
			},
			reason: core.ReasonDNSFailure, denyName: "b.example.com", aCalls: n(2)},
		{name: "direct mode uses the same rules", mode: core.ModeDirect, names: []string{"a.example.com"},
			setup: pointHere("a.example.com"), allowed: true, reason: core.ReasonDNSIPMatch, aCalls: n(1)},
		{name: "direct mode wildcard needs wildcard grant", mode: core.ModeDirect, names: []string{"*.example.com"},
			reason: core.ReasonWildcardGrantRequired, denyName: "*.example.com", aCalls: n(0)},
	})
}

func TestAuthorizeErrors(t *testing.T) {
	set := names.MustSet("a.example.com")
	src := netip.MustParseAddr(srcIP)

	e := newEnv()
	e.grants.err = errors.New("disk on fire")
	if _, err := e.gate.Authorize(context.Background(), core.ModeACME, src, set); err == nil {
		t.Fatal("grant store failure must be an error")
	}

	e = newEnv()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := e.gate.Authorize(ctx, core.ModeACME, src, set); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled ctx: err = %v", err)
	}

	// ctx ends while a lookup is in flight: no decision, an error.
	for _, mode := range []core.Mode{core.ModeACME, core.ModeDNSProxy} {
		e = newEnv()
		e.res.SetA("a.example.com", srcIP)
		ctx, cancel = context.WithCancel(context.Background())
		g := New(coretest.NewFakeConfig(nil), e.grants, &cancelling{Resolver: e.res, cancel: cancel, mode: mode}, e.providers)
		if d, err := g.Authorize(ctx, mode, src, set); !errors.Is(err, context.Canceled) {
			t.Fatalf("%s: ctx ended during lookup: got %+v, %v", mode, d, err)
		}
	}

	e = newEnv()
	if _, err := e.gate.Authorize(context.Background(), core.ModeUI, src, set); err == nil {
		t.Fatal("ui mode must be rejected")
	}
}

// cancelling cancels the caller's context during the lookup that decides
// (A in acme mode, CAA in dnsproxy mode) and fails like a resolver would.
type cancelling struct {
	core.Resolver
	cancel func()
	mode   core.Mode
}

func (c *cancelling) LookupA(ctx context.Context, name string) ([]netip.Addr, error) {
	if c.mode == core.ModeACME {
		c.cancel()
		return nil, ctx.Err()
	}
	return c.Resolver.LookupA(ctx, name)
}

func (c *cancelling) LookupCAA(ctx context.Context, name string) ([]core.CAA, error) {
	c.cancel()
	return nil, ctx.Err()
}

func TestAuthorizeDNSProxyCAA(t *testing.T) {
	const host = "host.example.com"
	// base: host resolves to the requester; extra CAA setup per case.
	with := func(f func(e *env)) func(e *env) {
		return func(e *env) {
			e.res.SetA(host, srcIP)
			if f != nil {
				f(e)
			}
		}
	}
	proxy := func(c authCase) authCase {
		c.mode = core.ModeDNSProxy
		if c.names == nil {
			c.names = []string{host}
		}
		if c.reason == "" {
			c.reason = core.ReasonWildcardUnprotected
		}
		if c.reason == core.ReasonWildcardUnprotected && c.denyName == "" {
			c.denyName = host
		}
		return c
	}
	ok := core.ReasonDNSIPMatch
	tests := []authCase{
		proxy(authCase{name: "no CAA anywhere", setup: with(nil), detail: "no CAA records", caaCalls: n(3)}),
		proxy(authCase{name: "issue only, pinned to broker", allowed: true, reason: ok,
			setup: with(func(e *env) { e.res.SetCAA("example.com", issue(pinned("primary.test", primaryAcct))) })}),
		proxy(authCase{name: "issue only, two providers pinned", allowed: true, reason: ok,
			setup: with(func(e *env) {
				e.res.SetCAA("example.com", issue(pinned("primary.test", primaryAcct)), issue(pinned("fallback.test", fallbackAcc)))
			})}),
		proxy(authCase{name: "issue only, one provider unpinned", detail: "not pinned",
			setup: with(func(e *env) {
				e.res.SetCAA("example.com", issue(pinned("primary.test", primaryAcct)), issue("fallback.test"))
			})}),
		proxy(authCase{name: "issue only, unpinned", detail: "not pinned",
			setup: with(func(e *env) { e.res.SetCAA("example.com", issue("primary.test")) })}),
		proxy(authCase{name: "issuewild ; overrides open issue", allowed: true, reason: ok,
			setup: with(func(e *env) { e.res.SetCAA("example.com", issue("primary.test"), issue("othe.ca"), issuewild(";")) })}),
		proxy(authCase{name: "issuewild empty value forbids all", allowed: true, reason: ok,
			setup: with(func(e *env) { e.res.SetCAA("example.com", issue("primary.test"), issuewild("")) })}),
		proxy(authCase{name: "issuewild pinned to broker", allowed: true, reason: ok,
			setup: with(func(e *env) {
				e.res.SetCAA("example.com", issue("primary.test"), issuewild(pinned("primary.test", primaryAcct)))
			})}),
		proxy(authCase{name: "issuewild ; and pinned", allowed: true, reason: ok,
			setup: with(func(e *env) {
				e.res.SetCAA("example.com", issuewild(";"), issuewild(pinned("fallback.test", fallbackAcc)))
			})}),
		proxy(authCase{name: "issuewild pinned to another account", detail: "not the broker's account",
			setup: with(func(e *env) {
				e.res.SetCAA("example.com", issuewild(pinned("primary.test", "https://primary.test/acme/acct/666")))
			})}),
		proxy(authCase{name: "issuewild unpinned, issue pinned", detail: "not pinned",
			setup: with(func(e *env) {
				e.res.SetCAA("example.com", issue(pinned("primary.test", primaryAcct)), issuewild("primary.test"))
			})}),
		proxy(authCase{name: "provider does not honour accounturi", detail: "does not honour",
			setup: with(func(e *env) {
				c := e.fallback.Caps()
				c.AccountURIHonoured = false
				e.fallback.SetCaps(c)
				e.res.SetCAA("example.com", issuewild(pinned("fallback.test", fallbackAcc)))
			})}),
		proxy(authCase{name: "issuer is not a provider", detail: "not an enabled provider",
			setup: with(func(e *env) {
				e.res.SetCAA("example.com", issuewild(pinned("letsencrypt.org", primaryAcct)))
			})}),
		proxy(authCase{name: "issuer of a disabled provider", detail: "not an enabled provider",
			setup: with(func(e *env) {
				e.providers.SetDisabled("fallback", true)
				e.res.SetCAA("example.com", issuewild(pinned("fallback.test", fallbackAcc)))
			})}),
		proxy(authCase{name: "account URL unavailable", detail: "unknown",
			setup: with(func(e *env) {
				e.primary.Inject(coretest.Fault{Op: coretest.OpAccountURL, Err: e.primary.Down()})
				e.res.SetCAA("example.com", issuewild(pinned("primary.test", primaryAcct)))
			})}),
		proxy(authCase{name: "whitespace and case", allowed: true, reason: ok,
			setup: with(func(e *env) {
				e.res.SetCAA("example.com", core.CAA{Flag: 128, Tag: "issuewild",
					Value: " \tPrimary.TEST ;  accounturi = " + primaryAcct + " ; validationmethods=dns-01 "})
			})}),
		proxy(authCase{name: "accounturi tag in another case", detail: "lower case",
			setup: with(func(e *env) {
				e.res.SetCAA("example.com", issuewild("primary.test; AccountURI="+primaryAcct))
			})}),
		proxy(authCase{name: "two accounturi, one foreign", detail: "not the broker's account",
			setup: with(func(e *env) {
				e.res.SetCAA("example.com", issuewild(pinned("primary.test", primaryAcct)+"; accounturi=https://x.test/1"))
			})}),
		proxy(authCase{name: "malformed value", detail: "malformed",
			setup: with(func(e *env) { e.res.SetCAA("example.com", issuewild("primary.test; accounturi")) })}),
		proxy(authCase{name: "only iodef at the node", detail: "no issue or issuewild",
			setup: with(func(e *env) { e.res.SetCAA("example.com", core.CAA{Tag: "iodef", Value: "mailto:x@example.com"}) })}),
		proxy(authCase{name: "CAA on parent applies to child", allowed: true, reason: ok, caaCalls: n(2),
			setup: with(func(e *env) { e.res.SetCAA("example.com", issuewild(";")) })}),
		proxy(authCase{name: "CAA on child wins over pinned parent", detail: "at host.example.com", caaCalls: n(1),
			setup: with(func(e *env) {
				e.res.SetCAA("example.com", issuewild(";"))
				e.res.SetCAA(host, issue("primary.test"))
			})}),
		proxy(authCase{name: "pinned child, open parent", allowed: true, reason: ok, caaCalls: n(1),
			setup: with(func(e *env) {
				e.res.SetCAA("example.com", issue("othe.ca"))
				e.res.SetCAA(host, issuewild(";"))
			})}),
		proxy(authCase{name: "CNAME node uses the target's CAA", allowed: true, reason: ok,
			setup: func(e *env) {
				e.res.SetCNAME(host, "lb.example.net")
				e.res.SetA("lb.example.net", srcIP)
				e.res.SetCAA("lb.example.net", issuewild(pinned("primary.test", primaryAcct)))
				e.res.SetCAA("example.com", issue("othe.ca"))
			}}),
		proxy(authCase{name: "CNAME node without CAA climbs the original tree", detail: "at example.com",
			setup: func(e *env) {
				e.res.SetCNAME(host, "lb.example.net")
				e.res.SetA("lb.example.net", srcIP)
				e.res.SetCAA("example.net", issuewild(";")) // the target's parent is not consulted
				e.res.SetCAA("example.com", issue("othe.ca"))
			}}),
		proxy(authCase{name: "CAA lookup failure", reason: core.ReasonDNSFailure, denyName: host,
			setup: with(func(e *env) { e.res.Fail("example.com", core.ErrResolver) })}),
		proxy(authCase{name: "DNS mismatch is decided before CAA", reason: core.ReasonDNSMismatch, denyName: host,
			caaCalls: n(0), aCalls: n(1)}),
		proxy(authCase{name: "multi-name: every name checked", names: []string{host, "x.example.org"},
			denyName: "x.example.org",
			setup: with(func(e *env) {
				e.res.SetA("x.example.org", srcIP)
				e.res.SetCAA("example.com", issuewild(";"))
			})}),
		proxy(authCase{name: "ordinary grant still needs CAA",
			setup: func(e *env) { e.grant(srcIP+"/32", true, false) }, aCalls: n(0)}),
		proxy(authCase{name: "ordinary grant with CAA", allowed: true, reason: core.ReasonIPGrant, grantID: 1, aCalls: n(0),
			setup: func(e *env) {
				e.grant(srcIP+"/32", true, false)
				e.res.SetCAA("com", issuewild(";")) // up to the TLD
			}}),
		proxy(authCase{name: "wildcard grant skips CAA", allowed: true, reason: core.ReasonIPGrant, grantID: 1,
			names: []string{host, "*.example.com"}, aCalls: n(0), caaCalls: n(0),
			setup: func(e *env) { e.grant(srcIP+"/32", true, true) }}),

		// Operator-trusted accounts (zones[].trusted_accounts).
		proxy(authCase{name: "trusted: broker and two operator accounts", allowed: true, reason: ok,
			setup: with(func(e *env) {
				e.trust("example.com", operatorA, operatorB)
				e.res.SetCAA("example.com", issue("primary.test"), issue("fallback.test"),
					issuewild(pinned("primary.test", primaryAcct)),
					issuewild(pinned("primary.test", operatorA)),
					issuewild(pinned("primary.test", operatorB)))
			})}),
		proxy(authCase{name: "trusted: operator account only", allowed: true, reason: ok,
			setup: with(func(e *env) {
				e.trust("example.com", operatorA)
				e.res.SetCAA("example.com", issuewild(pinned("primary.test", operatorA)))
			})}),
		proxy(authCase{name: "trusted: broker and operator in one value", allowed: true, reason: ok,
			setup: with(func(e *env) {
				e.trust("example.com", operatorA)
				e.res.SetCAA("example.com", issuewild(pinned("primary.test", primaryAcct)+"; accounturi="+operatorA))
			})}),
		proxy(authCase{name: "trusted: issue judged when there is no issuewild", allowed: true, reason: ok,
			setup: with(func(e *env) {
				e.trust("example.com", operatorA)
				e.res.SetCAA("example.com", issue(pinned("primary.test", primaryAcct)), issue(pinned("primary.test", operatorA)))
			})}),
		proxy(authCase{name: "trusted: operator account needs no broker account URL", allowed: true, reason: ok,
			setup: with(func(e *env) {
				e.trust("example.com", operatorA)
				e.primary.Inject(coretest.Fault{Op: coretest.OpAccountURL, Err: e.primary.Down()})
				e.res.SetCAA("example.com", issuewild(pinned("primary.test", operatorA)))
			})}),
		proxy(authCase{name: "trusted: an untrusted foreign account still unprotects",
			detail: "accounturi " + operatorB + " is not the broker's account at primary.test nor a trusted account of zone example.com",
			setup: with(func(e *env) {
				e.trust("example.com", operatorA)
				e.res.SetCAA("example.com", issuewild(pinned("primary.test", primaryAcct)),
					issuewild(pinned("primary.test", operatorA)), issuewild(pinned("primary.test", operatorB)))
			})}),
		proxy(authCase{name: "trusted: foreign account beside a trusted one in one value", detail: "nor a trusted account",
			setup: with(func(e *env) {
				e.trust("example.com", operatorA)
				e.res.SetCAA("example.com", issuewild(pinned("primary.test", operatorA)+"; accounturi="+operatorB))
			})}),
		proxy(authCase{name: "trusted: another zone's list does not apply", detail: "is not the broker's account",
			setup: with(func(e *env) {
				e.trust("example.org", operatorA)
				e.res.SetCAA("example.com", issuewild(pinned("primary.test", operatorA)))
			})}),
		proxy(authCase{name: "trusted: compared exactly", detail: "nor a trusted account",
			setup: with(func(e *env) {
				e.trust("example.com", operatorA)
				e.res.SetCAA("example.com", issuewild(pinned("primary.test", strings.ToUpper(operatorA))))
			})}),
		proxy(authCase{name: "trusted: provider does not honour accounturi", detail: "does not honour",
			setup: with(func(e *env) {
				e.trust("example.com", "https://fallback.test/acme/acct/7")
				c := e.fallback.Caps()
				c.AccountURIHonoured = false
				e.fallback.SetCaps(c)
				e.res.SetCAA("example.com", issuewild(pinned("fallback.test", "https://fallback.test/acme/acct/7")))
			})}),
		proxy(authCase{name: "trusted: issuer is not a provider", detail: "not an enabled provider",
			setup: with(func(e *env) {
				e.trust("example.com", operatorA)
				e.res.SetCAA("example.com", issuewild(pinned("letsencrypt.org", operatorA)))
			})}),
		proxy(authCase{name: "trusted: accounturi tag in another case", detail: "lower case",
			setup: with(func(e *env) {
				e.trust("example.com", operatorA)
				e.res.SetCAA("example.com", issuewild("primary.test; AccountURI="+operatorA))
			})}),
		proxy(authCase{name: "trusted: unpinned value still unprotects", detail: "not pinned",
			setup: with(func(e *env) {
				e.trust("example.com", operatorA)
				e.res.SetCAA("example.com", issuewild(pinned("primary.test", operatorA)), issuewild("primary.test"))
			})}),
	}
	runAuth(t, tests)
}

// Trusted accounts come from the configuration in effect for each call: a
// new generation applies without a restart.
func TestTrustedAccountsFollowConfig(t *testing.T) {
	e := newEnv()
	e.res.SetCAA("example.com", issuewild(pinned("primary.test", primaryAcct)), issuewild(pinned("primary.test", operatorA)))
	check := func(want bool) {
		t.Helper()
		st, err := e.gate.CheckCAA(context.Background(), "example.com")
		if err != nil || st.WildcardProtected != want {
			t.Fatalf("protected = %v (%s), want %v; err %v", st.WildcardProtected, st.Detail, want, err)
		}
	}
	check(false)
	e.trust("example.com", operatorA)
	check(true)
	e.trust("example.com")
	check(false)
}

func TestCheckCAA(t *testing.T) {
	tests := []struct {
		name      string
		check     string
		caa       map[string][]core.CAA
		setup     func(e *env)
		node      string
		protected bool
		missing   []string
		trusted   []string
		detail    string
	}{
		{name: "no CAA", check: "example.com", detail: "no CAA records"},
		{name: "broker only", check: "example.com",
			caa:  map[string][]core.CAA{"example.com": {issue(pinned("primary.test", primaryAcct)), issuewild(pinned("primary.test", primaryAcct))}},
			node: "example.com", protected: true, missing: []string{"fallback"},
			detail: "CAA issuewild at example.com allows *.example.com only to the broker's account at primary.test"},
		{name: "broker and trusted accounts", check: "example.com",
			caa: map[string][]core.CAA{"example.com": {issue("primary.test"), issue("fallback.test"),
				issuewild(pinned("primary.test", primaryAcct)), issuewild(pinned("primary.test", operatorA)),
				issuewild(pinned("primary.test", operatorB)), issuewild(pinned("primary.test", operatorA))}},
			setup: func(e *env) { e.trust("example.com", operatorA, operatorB) },
			node:  "example.com", protected: true, missing: []string{"fallback"}, trusted: []string{operatorA, operatorB},
			detail: "allows *.example.com only to the broker's account and 2 trusted accounts at primary.test (trusted accounts of zone example.com: " +
				operatorA + ", " + operatorB + ")"},
		{name: "trusted account only, two issuers", check: "example.com",
			caa:   map[string][]core.CAA{"example.com": {issuewild(pinned("primary.test", operatorA)), issuewild(pinned("fallback.test", fallbackAcc))}},
			setup: func(e *env) { e.trust("example.com", operatorA) },
			node:  "example.com", protected: true, missing: []string{"primary"}, trusted: []string{operatorA},
			detail: "only to 1 trusted account at primary.test, the broker's account at fallback.test"},
		{name: "trusted list of the zone holding the name", check: "*.sub.example.com",
			caa:   map[string][]core.CAA{"example.com": {issuewild(pinned("primary.test", operatorA))}},
			setup: func(e *env) { e.trust("example.com", operatorA) },
			node:  "example.com", protected: true, missing: []string{"primary", "fallback"}, trusted: []string{operatorA}},
		{name: "issue pinned to primary only", check: "example.com",
			caa:  map[string][]core.CAA{"example.com": {issue(pinned("primary.test", primaryAcct))}},
			node: "example.com", protected: true, missing: []string{"fallback"}},
		{name: "everything pinned, wildcards closed", check: "example.com",
			caa: map[string][]core.CAA{"example.com": {
				issue(pinned("primary.test", primaryAcct)), issue(pinned("fallback.test", fallbackAcc)), issuewild(";")}},
			node: "example.com", protected: true},
		{name: "issuewild ; only", check: "example.com",
			caa:  map[string][]core.CAA{"example.com": {issuewild(";")}},
			node: "example.com", protected: true, detail: "forbids every CA"},
		{name: "pinned to foreign accounts", check: "example.com",
			caa: map[string][]core.CAA{"example.com": {
				issue(pinned("primary.test", "https://primary.test/acme/acct/9")), issue("fallback.test")}},
			node: "example.com", missing: []string{"primary"}},
		{name: "fallback without accounturi support is permitted but breaks protection", check: "example.com",
			caa: map[string][]core.CAA{"example.com": {
				issue(pinned("primary.test", primaryAcct)), issue(pinned("fallback.test", fallbackAcc))}},
			setup: func(e *env) {
				c := e.fallback.Caps()
				c.AccountURIHonoured = false
				e.fallback.SetCaps(c)
			},
			node: "example.com", detail: "does not honour"},
		{name: "wildcard name and climbing", check: "*.sub.example.com",
			caa:  map[string][]core.CAA{"example.com": {issuewild(";"), issue("primary.test"), issue("fallback.test")}},
			node: "example.com", protected: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			e := newEnv()
			for n, rrs := range tc.caa {
				e.res.SetCAA(n, rrs...)
			}
			if tc.setup != nil {
				tc.setup(e)
			}
			st, err := e.gate.CheckCAA(context.Background(), tc.check)
			if err != nil {
				t.Fatal(err)
			}
			if st.Name != names.Base(tc.check) || st.Node != tc.node || st.WildcardProtected != tc.protected ||
				!slices.Equal(st.MissingProviders, tc.missing) || !slices.Equal(st.Records, tc.caa[tc.node]) ||
				!slices.Equal(st.TrustedAccounts, tc.trusted) {
				t.Fatalf("status = %+v", st)
			}
			if tc.detail != "" && !strings.Contains(st.Detail, tc.detail) {
				t.Fatalf("detail %q does not contain %q", st.Detail, tc.detail)
			}
		})
	}
	t.Run("resolution failure", func(t *testing.T) {
		e := newEnv()
		e.res.FailAll(core.ErrResolver)
		if _, err := e.gate.CheckCAA(context.Background(), "example.com"); !errors.Is(err, core.ErrResolver) {
			t.Fatalf("err = %v", err)
		}
	})
}

func TestParseIssueValue(t *testing.T) {
	tests := []struct {
		raw      string
		issuer   string
		accounts []string
		badTag   bool
		err      bool
	}{
		{raw: ";"},
		{raw: ""},
		{raw: "  ;  "},
		{raw: "letsencrypt.org", issuer: "letsencrypt.org"},
		{raw: "LetsEncrypt.ORG;", issuer: "letsencrypt.org"},
		{raw: "ca.test; accounturi=https://ca.test/a/1", issuer: "ca.test", accounts: []string{"https://ca.test/a/1"}},
		{raw: "ca.test;accounturi=u1;validationmethods=dns-01;accounturi=u2", issuer: "ca.test", accounts: []string{"u1", "u2"}},
		{raw: "\tca.test \t; \taccounturi \t=\t u ; ;", issuer: "ca.test", accounts: []string{"u"}},
		{raw: "ca.test; AccountUri=u", issuer: "ca.test", badTag: true},
		{raw: "; accounturi=u", accounts: []string{"u"}},
		{raw: "ca..test", err: true},
		{raw: "-ca.test", err: true},
		{raw: "ca.test.", err: true},
		{raw: "ca test", err: true},
		{raw: "ca.test; accounturi", err: true},
		{raw: "ca.test; accounturi=a b", err: true},
		{raw: "ca.test; =u", err: true},
		{raw: "ca.test; account_uri=u", err: true},
	}
	for _, tc := range tests {
		v, err := parseIssueValue(tc.raw)
		if (err != nil) != tc.err {
			t.Errorf("%q: err = %v, want error %v", tc.raw, err, tc.err)
			continue
		}
		if err != nil {
			continue
		}
		if v.issuer != tc.issuer || !slices.Equal(v.accountURIs, tc.accounts) || v.badAccountTag != tc.badTag {
			t.Errorf("%q: got %+v", tc.raw, v)
		}
	}
}

// The records the operator publishes (example.com, dev.example.com with its own
// CAA node, example.org; example names and URLs here): open issue for both
// CAs, issuewild pinned to the broker and to the operator's certbot accounts
// listed as trusted accounts of the zone. All are protected; dropping an
// account from trusted_accounts unprotects the nodes that name it.
func TestOperatorCAAFixture(t *testing.T) {
	const opC = "https://primary.test/acme/acct/333333333"
	setup := func(e *env) {
		open := []core.CAA{issue("primary.test"), issue("fallback.test")}
		e.res.SetCAA("example.com", append(slices.Clone(open),
			issuewild(pinned("primary.test", primaryAcct)), issuewild(pinned("primary.test", operatorA)))...)
		e.res.SetCAA("dev.example.com", append(slices.Clone(open), issuewild(pinned("primary.test", primaryAcct)),
			issuewild(pinned("primary.test", operatorA)), issuewild(pinned("primary.test", operatorB)))...)
		e.res.SetCAA("example.org", append(slices.Clone(open),
			issuewild(pinned("primary.test", primaryAcct)), issuewild(pinned("primary.test", opC)))...)
		e.trust("example.com", operatorA, operatorB)
		e.trust("example.org", opC)
	}
	cases := []struct {
		name, node, detail string
		trusted            []string
	}{
		{"example.com", "example.com", "only to the broker's account and 1 trusted account at primary.test", []string{operatorA}},
		{"dev.example.com", "dev.example.com", "only to the broker's account and 2 trusted accounts at primary.test", []string{operatorA, operatorB}},
		{"host.dev.example.com", "dev.example.com", "2 trusted accounts", []string{operatorA, operatorB}},
		{"example.org", "example.org", "only to the broker's account and 1 trusted account at primary.test", []string{opC}},
	}
	e := newEnv()
	setup(e)
	for _, tc := range cases {
		st, err := e.gate.CheckCAA(context.Background(), tc.name)
		if err != nil || !st.WildcardProtected || st.Node != tc.node || !strings.Contains(st.Detail, tc.detail) ||
			!slices.Equal(st.TrustedAccounts, tc.trusted) || len(st.MissingProviders) != 1 || st.MissingProviders[0] != "fallback" {
			t.Fatalf("%s: %+v %v", tc.name, st, err)
		}
	}
	// The DNS proxy serves a non-wildcard requester for these names.
	for _, name := range []string{"www.example.com", "x.dev.example.com", "example.org"} {
		e.res.SetA(name, srcIP)
		d, err := e.gate.Authorize(context.Background(), core.ModeDNSProxy, netip.MustParseAddr(srcIP), names.MustSet(name))
		if err != nil || !d.Allowed {
			t.Fatalf("%s: %+v %v", name, d, err)
		}
	}
	// Without operatorB in the list, dev.example.com is unprotected again.
	e.trust("example.com", operatorA)
	if st, _ := e.gate.CheckCAA(context.Background(), "dev.example.com"); st.WildcardProtected ||
		!strings.Contains(st.Detail, operatorB+" is not the broker's account at primary.test nor a trusted account of zone example.com") {
		t.Fatalf("dev.example.com without operatorB: %+v", st)
	}
}
