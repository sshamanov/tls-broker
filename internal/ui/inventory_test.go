package ui

import (
	"strings"
	"sync"
	"testing"
	"time"

	"tls-broker/internal/ctlog"
)

// invStub is a fixed CT inventory.
type invStub struct {
	mu sync.Mutex
	s  ctlog.Snapshot
}

func (i *invStub) Snapshot() ctlog.Snapshot { i.mu.Lock(); defer i.mu.Unlock(); return i.s }
func (i *invStub) set(s ctlog.Snapshot)     { i.mu.Lock(); i.s = s; i.mu.Unlock() }

const ctDay = 24 * time.Hour

// ctSnapshot is a loaded inventory at now for example.com: one certificate
// the broker issued (serial of seedCert "c1"), one expired outside it, one
// due for renewal with a recent renewal of another set, one from a CA the
// CAA does not allow.
func ctSnapshot(now time.Time) ctlog.Snapshot {
	le := func(tbs string, age, life time.Duration, serial string, names ...string) ctlog.Issuance {
		nb := now.Add(-age)
		return ctlog.Issuance{ID: tbs, TBSSHA256: tbs, Serial: serial, Names: names, NotBefore: nb, NotAfter: nb.Add(life),
			Issuer: "Let's Encrypt", IssuerCAA: []string{"letsencrypt.org"}}
	}
	google := le("g1", 3*ctDay, 90*ctDay, "", "rogue.example.com")
	google.Issuer, google.IssuerCAA = "Google Trust Services", []string{"pki.goog"}
	return ctlog.Snapshot{
		Enabled: true, Interval: 4 * time.Hour, LastRun: now.Add(-3 * time.Hour), LastEnd: now.Add(-3 * time.Hour), NextRun: now.Add(time.Hour),
		Zones:        []ctlog.ZoneStatus{{Zone: "example.com", LastAttempt: now.Add(-3 * time.Hour), LastSuccess: now.Add(-3 * time.Hour), Count: 6}},
		ManagedZones: []string{"example.com"},
		CAA:          map[string]ctlog.CAAPolicy{"example.com": {Node: "example.com", HasIssue: true, Issue: []string{"letsencrypt.org"}}},
		Issuances: []ctlog.Issuance{
			le("b1", 2*ctDay, 90*ctDay, "AC1", "www.example.com"),
			le("x1", 95*ctDay, 90*ctDay, "", "lapsed.example.com"),
			le("d1", 65*ctDay, 90*ctDay, "", "due.example.com"),
			le("r0", 70*ctDay, 90*ctDay, "", "api.example.com"),
			le("r1", 1*ctDay, 90*ctDay, "", "api.example.com"),
			google,
		},
	}
}

func TestCTPanels(t *testing.T) {
	inv := &invStub{}
	e := newEnv(t)
	seedCert(t, e, "c1", "www.example.com") // serial 0ac1
	bob := e.login("bob")
	admin := e.login("alice")

	// Not wired: switched off; the broker's own panels stay below.
	r := bob.get("/ui/")
	see(t, r, "Certificates in managed zones", "Issuance in the last 14 days", "The Certificate Transparency inventory is switched off",
		"Expiring next (broker)", "Recent issuance (broker)")
	lacks(t, r, "ct_inventory.disabled")
	see(t, admin.get("/ui/"), "<code>ct_inventory.disabled</code>")

	e.h.Inventory = inv
	inv.set(ctlog.Snapshot{Enabled: true, ManagedZones: []string{"example.com"}, Zones: []ctlog.ZoneStatus{{Zone: "example.com"}}})
	see(t, bob.get("/ui/"), "Reading Certificate Transparency logs")

	now := e.clock.Now()
	inv.set(ctSnapshot(now))
	r = bob.get("/ui/")
	see(t, r, "5 current certificates in 1 zone; ", "2 need attention", "Updated 3h00m ago.",
		"<code>lapsed.example.com</code>", `<span class="pill bad">expired</span>`, `<span class="pill caution">renewal due</span>`,
		`<span class="pill bad">unexpected CA</span>`, "Google Trust Services is not allowed by the CAA issue records of example.com (allowed: letsencrypt.org)",
		"Let&#39;s Encrypt, via the broker", "Let&#39;s Encrypt, outside the broker",
		"3 certificates issued: 1 renewal and 2 for new or changed names.", `<span class="pill ok">renewal</span>`, `<span class="pill info">new names</span>`,
		"Expiring next (broker)")
	lacks(t, r, "Needs attention", "Certificate Transparency: ")
	// Problems first: the expired set leads the panel.
	if i, j := strings.Index(r.body, "lapsed.example.com"), strings.Index(r.body, "due.example.com"); i < 0 || j < 0 || i > j {
		t.Errorf("expired must come before due (%d, %d)", i, j)
	}

	r = admin.get("/ui/")
	for _, el := range []string{"div", "section", "ul", "li"} {
		if o, c := strings.Count(r.body, "<"+el+">")+strings.Count(r.body, "<"+el+" "), strings.Count(r.body, "</"+el+">"); o != c {
			t.Errorf("status page: %d <%s> opened, %d closed", o, el, c)
		}
	}
	see(t, r, "Needs attention", "Certificate Transparency: 1 certificate expired without a renewal: lapsed.example.com.",
		"Certificate Transparency: 1 certificate from a CA the zone&#39;s CAA does not allow: rogue.example.com: Google Trust Services")

	// A zone that failed: users see that the data is partly stale, admins
	// also the error.
	s := ctSnapshot(now)
	s.Zones[0].Err = "rate limited by the Certificate Transparency source (retry after 1h0m0s)"
	inv.set(s)
	r = bob.get("/ui/")
	see(t, r, "Partly out of date: <code>example.com</code> could not be refreshed. It is tried again in 1h00m.")
	lacks(t, r, "retry after 1h0m0s")
	r = admin.get("/ui/")
	see(t, r, "could not be refreshed (rate limited by the Certificate Transparency source (retry after 1h0m0s))",
		"Certificate Transparency: zone example.com could not be refreshed (last success 2026-10-02 09:00:00 UTC): rate limited")

	// Nothing known and every zone failed: not available.
	inv.set(ctlog.Snapshot{Enabled: true, LastEnd: now, NextRun: now.Add(15 * time.Minute), ManagedZones: []string{"example.com"},
		Zones: []ctlog.ZoneStatus{{Zone: "example.com", LastAttempt: now, Err: "dial tcp: connection refused"}}})
	r = bob.get("/ui/")
	see(t, r, "The inventory is not available right now")
	lacks(t, r, "connection refused")
	see(t, admin.get("/ui/"), "<code>example.com</code>: dial tcp: connection refused")
}

func TestCTList(t *testing.T) {
	inv := &invStub{}
	e := newEnv(t)
	e.h.Inventory = inv
	seedCert(t, e, "c1", "www.example.com")
	inv.set(ctSnapshot(e.clock.Now()))
	bob := e.login("bob")

	r := bob.get("/ui/certificates/zones")
	code(t, r, 200)
	see(t, r, `<a href="/ui/certificates/zones" aria-current="page">All in managed zones</a>`, "5 sets of names in 1 zone, 6 certificates",
		"lapsed.example.com", "www.example.com", "rogue.example.com", "<summary>1</summary>", "serial <code>AC1</code>")
	see(t, bob.get("/ui/certificates"), `<a href="/ui/certificates" aria-current="page">Issued by the broker</a>`)

	r = bob.get("/ui/certificates/zones?state=attention")
	see(t, r, "lapsed.example.com", "rogue.example.com")
	lacks(t, r, "due.example.com", "www.example.com")
	r = bob.get("/ui/certificates/zones?source=broker")
	see(t, r, "www.example.com")
	lacks(t, r, "lapsed.example.com")
	r = bob.get("/ui/certificates/zones?state=due&q=due")
	see(t, r, "due.example.com")
	lacks(t, r, "lapsed.example.com")
	see(t, bob.get("/ui/certificates/zones?zone=example.org"), "No certificates match the filter.")

	// Blocked users see no certificates.
	e.store.Users().SetBlocked(bg, e.userID("bob"), true)
	code(t, bob.get("/ui/certificates/zones"), 403)
}
