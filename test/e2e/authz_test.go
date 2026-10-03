package e2e

import (
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/go-acme/lego/v5/acme"

	"tls-broker/internal/core"
	"tls-broker/internal/core/coretest"
)

// denied asserts an ACME 403 unauthorized naming reason.
func deniedACME(t *testing.T, err error, reason string) {
	t.Helper()
	pd := problem(t, err)
	if pd.HTTPStatus != http.StatusForbidden || pd.Type != acme.UnauthorizedErrorType || !strings.Contains(pd.Detail, reason) {
		t.Fatalf("want 403 unauthorized %s, got %+v", reason, pd)
	}
}

// Blocked users and grant failures: a blocked user cannot create grants;
// a disabled grant authorizes nothing; an enabled grant authorizes even
// names that do not resolve to the host (and survives its owner being
// blocked: grants are not tied to the owner's state, architecture §4.2).
func testBlockedAndGrants(t *testing.T) {
	b := newFakeBroker(t)
	ctx := t.Context()

	// Blocked user in the UI.
	carol := b.user("carol")
	if err := b.app().Store().Users().SetBlocked(ctx, carol.ID, true); err != nil {
		t.Fatal(err)
	}
	ui := b.machine("10.0.9.1").browser()
	ui.login("carol", "carol-pw")
	if code, body := ui.do(http.MethodPost, "/ui/grants", url.Values{"prefix": {"10.0.0.70"}}); code != http.StatusForbidden {
		t.Fatalf("blocked user created a grant: %d %.200s", code, body)
	}
	if gs, _ := b.app().Store().Grants().List(ctx, carol.ID); len(gs) != 0 {
		t.Fatalf("grants of the blocked user: %+v", gs)
	}

	// A host whose name points elsewhere, with a disabled grant.
	m := b.machine("10.0.0.70")
	b.dns.SetA("granted.example.com", "192.0.2.1")
	g := b.grant("10.0.0.70", false)
	g.Enabled = false
	if err := b.app().Store().Grants().Update(ctx, g); err != nil {
		t.Fatal(err)
	}
	c := m.acme()
	_, err := c.newOrder("", "granted.example.com")
	deniedACME(t, err, core.ReasonDNSMismatch)
	if code, _, _ := m.get("/cert/granted.example.com"); code != http.StatusForbidden {
		t.Fatalf("direct with a disabled grant: %d", code)
	}

	// Enabled: allowed by the grant, recorded on the order.
	g.Enabled = true
	if err := b.app().Store().Grants().Update(ctx, g); err != nil {
		t.Fatal(err)
	}
	is := c.issue("", "granted.example.com")
	if o := b.order(is.orderID); o.GrantID != g.ID {
		t.Fatalf("order grant %d, want %d", o.GrantID, g.ID)
	}
	// The owner is blocked: the grant still works.
	if err := b.app().Store().Users().SetBlocked(ctx, g.OwnerUserID, true); err != nil {
		t.Fatal(err)
	}
	if code, _, body := m.get("/cert/granted.example.com"); code != http.StatusOK {
		t.Fatalf("direct with the grant of a blocked owner: %d %s", code, body)
	}
	if evs := b.auditEvents(core.AuditGate); len(evs) == 0 {
		t.Fatal("no gate audit for the denials")
	}
	if s := b.le.Stats(); s.OrdersCreated != 2 {
		t.Fatalf("CA stats %+v", s)
	}
	b.checkInvariants(0)
}

// Wildcards need an explicit wildcard grant in all three modes, even when
// every name resolves to the host and an ordinary grant exists.
func testWildcardPermission(t *testing.T) {
	b := newFakeBroker(t)
	m := b.machine("10.0.0.80", "wild.example.com", "x.wild.example.com")
	b.dns.SetCAA("example.com", core.CAA{Tag: "issuewild", Value: ";"})
	g := b.grant("10.0.0.80", false)
	c := m.acme()

	_, err := c.newOrder("", "*.wild.example.com")
	deniedACME(t, err, core.ReasonWildcardGrantRequired)
	_, err = c.newOrder("", "*.wild.example.com", "wild.example.com")
	deniedACME(t, err, core.ReasonWildcardGrantRequired)
	if code, _, body := m.get("/cert/wildcard/wild.example.com"); code != http.StatusForbidden || !strings.Contains(string(body), core.ReasonWildcardGrantRequired) {
		t.Fatalf("direct wildcard: %d %s", code, body)
	}
	code, _, body := m.postJSON("/dns/present", `{"identifier":"*.wild.example.com","value":"wild-value-0123456789"}`)
	if code != http.StatusForbidden || !strings.Contains(string(body), "denied: "+core.ReasonWildcardGrantRequired) {
		t.Fatalf("dns proxy wildcard: %d %s", code, body)
	}
	if s := b.le.Stats(); s.OrdersCreated != 0 {
		t.Fatalf("upstream orders for denied wildcards: %+v", s)
	}
	if b.r53.Changes(zoneCOM) != 0 {
		t.Fatal("Route53 changed for a denied wildcard")
	}

	// With wildcard=true on the grant: all three modes succeed.
	g.Wildcard = true
	if err := b.app().Store().Grants().Update(t.Context(), g); err != nil {
		t.Fatal(err)
	}
	c.issue("", "*.wild.example.com", "wild.example.com")
	code, _, dc, body := m.fetch("wildcard/wild.example.com")
	if code != http.StatusOK {
		t.Fatalf("direct wildcard with grant: %d %s", code, body)
	}
	if _, err := b.le.VerifyChain(dc.chain, "x.wild.example.com"); err != nil {
		t.Fatal(err)
	}
	if code, _, body := m.postJSON("/dns/present", `{"identifier":"*.wild.example.com","value":"wild-value-0123456789"}`); code != http.StatusCreated {
		t.Fatalf("dns proxy wildcard with grant: %d %s", code, body)
	}
	b.checkInvariants(0)
}

// Every name of a multi-SAN order must resolve to the host: one name that
// points elsewhere denies the whole order, before anything reaches the CA.
func testMultiSANGate(t *testing.T) {
	b := newFakeBroker(t)
	m := b.machine("10.0.0.90", "a.example.com", "b.example.org")
	b.dns.SetA("c.example.com", "10.0.0.99")
	c := m.acme()

	_, err := c.newOrder("", "a.example.com", "b.example.org", "c.example.com")
	deniedACME(t, err, core.ReasonDNSMismatch)
	// A name that does not resolve at all is a mismatch too.
	_, err = c.newOrder("", "a.example.com", "nx.example.com")
	deniedACME(t, err, core.ReasonDNSMismatch)
	// A name outside the managed zones is rejected, not denied.
	_, err = c.newOrder("", "a.example.com", "www.unmanaged.test")
	if pd := problem(t, err); pd.Type != acme.RejectedIdentifierErrorType {
		t.Fatalf("unmanaged name: %+v", pd)
	}
	if s := b.le.Stats(); s.Calls[coretest.OpNewOrder] != 0 {
		t.Fatalf("upstream called for denied orders: %+v", s.Calls)
	}
	deny := 0
	for _, ev := range b.auditEvents(core.AuditGate) {
		if ev.Decision == core.AuditDecisionDeny && ev.Reason == core.ReasonDNSMismatch {
			deny++
		}
	}
	if deny != 2 {
		t.Fatalf("gate deny audit events: %d", deny)
	}

	b.dns.SetA("c.example.com", "10.0.0.90")
	is := c.issue("", "a.example.com", "b.example.org", "c.example.com")
	if o := b.order(is.orderID); o.GrantID != 0 {
		t.Fatalf("DNS-authorized order carries grant %d", o.GrantID)
	}
	b.checkInvariants(0)
}

type presented struct {
	ID     string `json:"challenge_id"`
	Record string `json:"record"`
	Value  string `json:"value"`
}

// The DNS proxy: present waits until the value is public and is
// idempotent; cleanup only by the presenting source; non-wildcard requests
// need CAA that closes the implicit wildcard (issuewild ";" or an
// accounturi pin to the broker's account) unless the source has a
// wildcard grant; stale values are swept.
func testDNSProxy(t *testing.T) {
	b := newFakeBroker(t)
	b.dns.SetCAA("example.org", core.CAA{Tag: "issuewild", Value: ";"})
	b.dns.SetCAA("pinned.example.com", core.CAA{Tag: "issue", Value: "letsencrypt.test; accounturi=https://letsencrypt.test/acme/acct/1"})
	m := b.machine("10.0.1.10", "host.example.org", "host.example.com", "pinned.example.com")
	other := b.machine("10.0.1.11")

	present := func(m *machine, id, value string, want int) presented {
		t.Helper()
		code, _, body := m.postJSON("/dns/present", `{"identifier":"`+id+`","value":"`+value+`"}`)
		if code != want {
			t.Fatalf("present %s from %s: %d %s", id, m.ip, code, body)
		}
		var p presented
		if code == http.StatusCreated {
			if err := json.Unmarshal(body, &p); err != nil {
				t.Fatal(err)
			}
		}
		return p
	}

	p := present(m, "host.example.org", "value-org-0123456789", http.StatusCreated)
	if p.Record != "_acme-challenge.host.example.org" || p.ID == "" {
		t.Fatalf("present response %+v", p)
	}
	if v := b.r53.TXT(p.Record); len(v) != 1 || v[0] != "value-org-0123456789" {
		t.Fatalf("published %v", v)
	}
	if again := present(m, "host.example.org", "value-org-0123456789", http.StatusCreated); again.ID != p.ID {
		t.Fatalf("repeat gave %s, want %s", again.ID, p.ID)
	}
	if code, _, body := m.get("/dns/challenges"); code != http.StatusOK || !strings.Contains(string(body), p.ID) {
		t.Fatalf("list: %d %s", code, body)
	}
	if code, _, _ := other.do(http.MethodDelete, "/dns/challenges/"+p.ID, nil); code != http.StatusForbidden {
		t.Fatalf("cleanup by another source: %d", code)
	}
	if code, _, _ := m.postJSON("/dns/cleanup", `{"challenge_id":"`+p.ID+`"}`); code != http.StatusNoContent {
		t.Fatalf("cleanup: %d", code)
	}
	if code, _, _ := m.do(http.MethodDelete, "/dns/challenges/"+p.ID, nil); code != http.StatusNoContent {
		t.Fatalf("second cleanup: %d", code)
	}
	if v := b.r53.TXT(p.Record); len(v) != 0 {
		t.Fatalf("value left after cleanup: %v", v)
	}

	// No CAA for example.com: the implicit wildcard is open, denied.
	code, _, body := m.postJSON("/dns/present", `{"identifier":"host.example.com","value":"value-com-0123456789"}`)
	if code != http.StatusForbidden || !strings.Contains(string(body), "denied: "+core.ReasonWildcardUnprotected) {
		t.Fatalf("CAA-unprotected present: %d %s", code, body)
	}
	// CAA pinned to the broker's account at the CA: allowed.
	present(m, "pinned.example.com", "value-pin-0123456789", http.StatusCreated)
	// A wildcard grant bypasses the CAA condition.
	b.grant("10.0.1.10", true)
	present(m, "host.example.com", "value-com-0123456789", http.StatusCreated)
	// Names that do not resolve to the source; names outside the zones.
	present(other, "host.example.org", "value-x-0123456789", http.StatusForbidden)
	present(m, "host.unmanaged.test", "value-y-0123456789", http.StatusNotFound)

	// Values nobody cleans up are swept after dns_proxy.challenge_ttl.
	b.advance(2 * time.Hour)
	b.housekeep()
	for _, rec := range []string{"_acme-challenge.pinned.example.com", "_acme-challenge.host.example.com"} {
		if v := b.r53.TXT(rec); len(v) != 0 {
			t.Fatalf("stale value at %s: %v", rec, v)
		}
	}
	if evs := b.auditEvents(core.AuditDNSPresent); len(evs) < 6 {
		t.Fatalf("dns_present audit events: %d", len(evs))
	}
	if s := b.le.Stats(); s.OrdersCreated != 0 {
		t.Fatal("the DNS proxy created upstream orders")
	}
	b.checkInvariants(0)
}

// The UI: an LDAP user logs in, creates a grant (CSRF-protected form), may
// not create a wildcard grant with the normal role, and sees the change in
// the audit log (admin-only there; the issuance it allows is public); the
// grant then authorizes a host.
func testUI(t *testing.T) {
	b := newFakeBroker(t)
	bob := b.machine("10.0.2.1").browser()
	if code, _ := bob.do(http.MethodPost, "/ui/login", url.Values{"username": {"bob"}, "password": {"wrong"}}); code != http.StatusUnauthorized {
		t.Fatalf("wrong password: %d", code)
	}
	bob.login("bob", "bob-pw")

	// Without the CSRF token the form is refused.
	tok := bob.csrf
	bob.csrf = ""
	if code, _ := bob.do(http.MethodPost, "/ui/grants", url.Values{"prefix": {"10.0.3.0/24"}}); code != http.StatusForbidden {
		t.Fatalf("grant without CSRF token: %d", code)
	}
	bob.csrf = tok
	if code, body := bob.do(http.MethodPost, "/ui/grants", url.Values{"prefix": {"10.0.3.0/24"}, "note": {"lab"}}); code != http.StatusSeeOther {
		t.Fatalf("create grant: %d %.300s", code, body)
	}
	if code, _ := bob.do(http.MethodPost, "/ui/grants", url.Values{"prefix": {"10.0.4.0/24"}, "wildcard": {"true"}}); code != http.StatusForbidden {
		t.Fatalf("wildcard grant with the normal role: %d", code)
	}
	if code, body := bob.do(http.MethodGet, "/ui/grants", nil); code != http.StatusOK || !strings.Contains(body, "10.0.3.0/24") {
		t.Fatalf("grants page: %d", code)
	}

	// An admin (bootstrap) sees the admin pages; bob does not.
	if code, _ := bob.do(http.MethodGet, "/ui/admin/users", nil); code != http.StatusForbidden {
		t.Fatalf("admin page for bob: %d", code)
	}
	alice := b.machine("10.0.2.2").browser()
	alice.login("alice", "alice-pw")
	if code, body := alice.do(http.MethodGet, "/ui/admin/users", nil); code != http.StatusOK || !strings.Contains(body, "bob") {
		t.Fatalf("admin users page: %d", code)
	}

	// The grant created in the UI authorizes a host in its prefix.
	m := b.machine("10.0.3.7")
	b.dns.SetA("lab.example.com", "192.0.2.7")
	m.acme().issue("", "lab.example.com")

	// Audit visibility: grant changes are admin-only, issuance is public.
	if code, body := alice.do(http.MethodGet, "/ui/audit", nil); code != http.StatusOK || !strings.Contains(body, "created grant 10.0.3.0/24") {
		t.Fatalf("admin audit page: %d", code)
	}
	code, body := bob.do(http.MethodGet, "/ui/audit", nil)
	if code != http.StatusOK || strings.Contains(body, "created grant 10.0.3.0/24") || !strings.Contains(body, "lab.example.com") {
		t.Fatalf("public audit page: %d", code)
	}
	if evs := b.auditEvents(core.AuditGrantChange); len(evs) != 1 || evs[0].Username != "bob" {
		t.Fatalf("grant_change audit %+v", evs)
	}
	if evs := b.auditEvents(core.AuditLogin); len(evs) < 3 {
		t.Fatalf("login audit events: %d", len(evs))
	}
	b.checkInvariants(0)
}
