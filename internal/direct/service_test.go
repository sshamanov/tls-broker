package direct

import (
	"bytes"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"tls-broker/internal/core"
)

const host = "dev.example.com"

func netip6() netip.Addr { return netip.MustParseAddr("2001:db8::1") }

func TestMissThenHit(t *testing.T) {
	e := newEnv(t)
	c := e.mustGet(host)
	e.wantCalls(1)
	call := e.iss.Calls()[0]
	if call.Identifier != host || call.Background || call.SourceIP != device || !call.Decision.Allowed {
		t.Fatalf("issue request %+v", call)
	}
	if c.Generation != 1 || c.Identifier != host || !bytes.HasPrefix(c.KeyPEM, []byte("-----BEGIN RSA PRIVATE KEY-----")) {
		t.Fatalf("cert %+v", c)
	}
	en := e.entry(host)
	if en.Generation != 1 || en.Provider != "primary" || en.CertificateID == "" || en.Failures != 0 ||
		!en.NotAfter.Equal(c.NotAfter) || !en.LastFetchAt.Equal(e.clock.Now()) || en.LastFetchIP != device {
		t.Fatalf("entry %+v", en)
	}
	if e.rec.misses.Load() != 1 || e.rec.hits.Load() != 0 {
		t.Fatalf("metrics hits=%d misses=%d", e.rec.hits.Load(), e.rec.misses.Load())
	}

	e.clock.Advance(time.Hour)
	c2 := e.mustGet(host)
	e.wantCalls(1)
	if c2.ETag() != c.ETag() || e.rec.hits.Load() != 1 {
		t.Fatalf("hit changed the certificate or was not counted")
	}
	// The first hit checks renewal information once (none is available).
	if e.iss.ARICalls() != 1 {
		t.Fatalf("ARI calls = %d", e.iss.ARICalls())
	}
	en = e.entry(host)
	if !en.NextARICheckAt.Equal(e.clock.Now().Add(6*time.Hour)) || en.RenewAt.IsZero() {
		t.Fatalf("schedule not recorded: %+v", en)
	}
	if lin, err := e.db.Lineages().Get(ctx, host); err != nil || lin.Samples != 1 {
		t.Fatalf("lineage %+v %v", lin, err)
	}
	fetches := e.aud.OfType(core.AuditDirectFetch)
	if len(fetches) != 2 || fetches[1].Result != core.AuditResultOK || fetches[1].Visibility != core.AuditVisibilityAll {
		t.Fatalf("audit %+v", fetches)
	}
}

// TestLifecycle walks the table of architecture §11 with a 90-day
// certificate: renewal due at 2/3 of the lifetime (day 60), emergency window
// 0.05*90d + 3*24h = 7.5 days before expiry.
func TestLifecycle(t *testing.T) {
	cases := []struct {
		name       string
		fraction   float64
		at         time.Duration // after the first issuance
		calls      int           // issuer calls after the fetch
		background bool          // the second call was a background renewal
		served     int           // generation served by this fetch
		detail     string
		// daily: the device fetched once a day until then, so the observed
		// check interval is one day (emergency window 7.5 days).
		daily bool
	}{
		{"valid", 2.0 / 3.0, 10 * day, 1, false, 1, "hit: generation 1", false},
		{"renewal due", 2.0 / 3.0, 61 * day, 2, true, 1, "background job started: renewal", false},
		{"emergency", 0.99, 83 * day, 2, true, 1, "renewal (emergency window)", true},
		{"not yet emergency", 0.99, 82 * day, 1, false, 1, "hit", true},
		{"expired", 2.0 / 3.0, 91 * day, 2, false, 2, "expired: issued generation 2", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e := newEnv(t, func(c *core.Config) { c.Direct.RenewFraction = tc.fraction })
			first := e.mustGet(host)
			if tc.daily {
				for range int(tc.at/day) - 1 {
					e.clock.Advance(day)
					e.mustGet(host)
				}
				e.clock.Advance(day)
			} else {
				e.clock.Advance(tc.at)
			}
			e.aud.Reset()
			c := e.mustGet(host)
			e.wantCalls(tc.calls)
			if c.Generation != tc.served {
				t.Fatalf("served generation %d, want %d", c.Generation, tc.served)
			}
			if tc.calls == 2 {
				if bg := e.iss.Calls()[1].Background; bg != tc.background {
					t.Fatalf("Background = %v", bg)
				}
				if en := e.entry(host); en.Generation != 2 {
					t.Fatalf("entry generation %d after renewal", en.Generation)
				}
				// The renewal reuses the key.
				next := e.mustGet(host)
				if next.Generation != 2 || !bytes.Equal(next.KeyPEM, first.KeyPEM) {
					t.Fatal("renewal did not keep the key")
				}
			}
			ev := e.aud.OfType(core.AuditDirectFetch)[0]
			if !strings.Contains(ev.Detail, tc.detail) || ev.Result != core.AuditResultOK {
				t.Fatalf("audit detail %q, want %q", ev.Detail, tc.detail)
			}
		})
	}
}

func TestRequestDrivenRenewal(t *testing.T) {
	e := newEnv(t)
	e.mustGet(host)
	// Nobody fetches: time passes through the renewal and emergency
	// windows without any upstream activity.
	for range 89 {
		e.clock.Advance(day)
	}
	e.idle()
	e.wantCalls(1)
	if e.iss.ARICalls() != 0 {
		t.Fatalf("ARI calls without fetches: %d", e.iss.ARICalls())
	}
	// The first fetch after all that starts the renewal.
	if c := e.mustGet(host); c.Generation != 1 {
		t.Fatalf("served generation %d", c.Generation)
	}
	e.wantCalls(2)
}

func TestARIWindowDrivesRenewal(t *testing.T) {
	e := newEnv(t)
	t0 := e.clock.Now()
	e.iss.set(func(f *fakeIssuer) {
		f.ari["*"] = core.RenewalInfo{WindowStart: t0.Add(30 * day), WindowEnd: t0.Add(32 * day), RetryAfter: 6 * time.Hour}
	})
	e.mustGet(host)
	e.clock.Advance(time.Hour)
	e.mustGet(host) // first hit reads ARI
	if got := e.entry(host).RenewAt; !got.Equal(t0.Add(30 * day)) {
		t.Fatalf("RenewAt = %v", got)
	}
	e.clock.Advance(20 * day)
	e.mustGet(host)
	e.wantCalls(1)
	e.clock.Advance(10 * day) // day 30 + 1h
	e.mustGet(host)
	e.wantCalls(2)
	if !e.iss.Calls()[1].Background {
		t.Fatal("ARI renewal was not a background renewal")
	}
}

func TestConcurrentMissesCollapse(t *testing.T) {
	e := newEnv(t)
	release := make(chan struct{})
	e.iss.set(func(f *fakeIssuer) { f.block = release })
	const n = 20
	var wg sync.WaitGroup
	results := make([]*Cert, n)
	errs := make([]error, n)
	for i := range n {
		wg.Add(1)
		go func() {
			defer wg.Done()
			results[i], errs[i] = e.svc.Get(ctx, device, host)
		}()
	}
	<-e.iss.started
	time.Sleep(50 * time.Millisecond) // let the others join the job
	close(release)
	wg.Wait()
	e.idle()
	e.wantCalls(1)
	for i := range n {
		if errs[i] != nil || results[i].Generation != 1 {
			t.Fatalf("request %d: %v", i, errs[i])
		}
	}
}

func TestUpstreamDownServesValidCertificate(t *testing.T) {
	e := newEnv(t)
	e.mustGet(host)
	e.clock.Advance(61 * day)
	e.iss.set(func(f *fakeIssuer) { f.failAll = &core.ProviderError{Provider: "primary", Kind: core.ProviderDown} })

	if c := e.mustGet(host); c.Generation != 1 {
		t.Fatalf("served generation %d", c.Generation)
	}
	e.wantCalls(2)
	en := e.entry(host)
	if en.Failures != 1 || en.LastError == "" || en.Generation != 1 || e.rec.renewFailed.Load() != 1 {
		t.Fatalf("failure not recorded: %+v", en)
	}
	// Inside the backoff (1 min) fetches are served without new attempts.
	e.clock.Advance(30 * time.Second)
	e.mustGet(host)
	e.wantCalls(2)
	e.clock.Advance(time.Minute)
	e.mustGet(host)
	e.wantCalls(3)
	// Backoff doubles: 2 minutes now.
	e.clock.Advance(90 * time.Second)
	e.mustGet(host)
	e.wantCalls(3)
	e.clock.Advance(time.Minute)
	e.iss.set(func(f *fakeIssuer) { f.failAll = nil })
	e.mustGet(host)
	e.wantCalls(4)
	if en := e.entry(host); en.Failures != 0 || en.Generation != 2 || en.LastError != "" {
		t.Fatalf("success did not reset the failure state: %+v", en)
	}
}

func TestExpiredAndUpstreamDown(t *testing.T) {
	e := newEnv(t)
	e.mustGet(host)
	e.clock.Advance(91 * day)
	e.iss.set(func(f *fakeIssuer) {
		f.failAll = &core.AdmissionError{Kind: core.AdmissionProviderDown, RetryAfter: 5 * time.Minute}
	})
	_, p := e.get(host)
	if p == nil || p.Status != http.StatusServiceUnavailable || p.RetryAfter != 5*time.Minute {
		t.Fatalf("problem %+v", p)
	}
	// Retried inside the hold: still 503, no new attempt.
	e.clock.Advance(time.Minute)
	_, p = e.get(host)
	if p == nil || p.Status != http.StatusServiceUnavailable || p.RetryAfter != 4*time.Minute {
		t.Fatalf("problem %+v", p)
	}
	e.wantCalls(2)
	if ev := e.aud.OfType(core.AuditDirectFetch); ev[len(ev)-1].Result != core.AuditResultFailed {
		t.Fatalf("audit %+v", ev[len(ev)-1])
	}
}

func TestRateLimitedPassthrough(t *testing.T) {
	e := newEnv(t)
	e.iss.set(func(f *fakeIssuer) {
		f.failAll = &core.AdmissionError{Kind: core.AdmissionRateLimited, RetryAfter: 2 * time.Hour, Reason: "certificates per exact set"}
	})
	_, p := e.get(host)
	if p == nil || p.Status != http.StatusTooManyRequests || p.Type != core.ProblemRateLimited || p.RetryAfter != 2*time.Hour {
		t.Fatalf("problem %+v", p)
	}
	e.clock.Advance(30 * time.Minute)
	_, p = e.get(host)
	if p == nil || p.Status != http.StatusTooManyRequests || p.RetryAfter != 90*time.Minute {
		t.Fatalf("second problem %+v", p)
	}
	e.wantCalls(1)
	if en := e.entry(host); en.Generation != 0 || en.Failures != 1 {
		t.Fatalf("entry %+v", en)
	}
}

func TestAuthorizationAndValidation(t *testing.T) {
	e := newEnv(t)
	e.gate.Decide(core.Decision{Reason: core.ReasonDNSMismatch, Name: host, Detail: "resolves to 192.0.2.99"})
	if _, p := e.get(host); p == nil || p.Status != http.StatusForbidden {
		t.Fatalf("gate denial: %+v", p)
	}
	e.gate.Decide(core.Decision{Reason: core.ReasonDNSFailure})
	if _, p := e.get(host); p == nil || p.Status != http.StatusServiceUnavailable || p.RetryAfter <= 0 {
		t.Fatalf("dns failure: %+v", p)
	}
	e.gate.DecideFunc(nil)
	for _, id := range []string{"host.other.net", "not a name", "10.0.0.1", "*.*.example.com"} {
		if _, p := e.get(id); p == nil || p.Status != http.StatusNotFound {
			t.Fatalf("%q: %+v", id, p)
		}
	}
	if _, err := e.svc.Get(ctx, netip6(), host); core.AsProblem(err) == nil || core.AsProblem(err).Status != http.StatusForbidden {
		t.Fatalf("IPv6 source: %v", err)
	}
	e.wantCalls(0)
	if len(e.gate.Calls()) != 2 {
		t.Fatalf("gate consulted %d times; only valid in-zone IPv4 requests reach it", len(e.gate.Calls()))
	}
	for _, ev := range e.aud.OfType(core.AuditDirectFetch) {
		if ev.Decision != core.AuditDecisionDeny || ev.Visibility != core.AuditVisibilityAdmin {
			t.Fatalf("audit %+v", ev)
		}
	}
	// A cached certificate is not served to a denied source either.
	e.mustGet(host)
	e.gate.Decide(core.Decision{Reason: core.ReasonWildcardGrantRequired})
	if _, p := e.get(host); p == nil || p.Status != http.StatusForbidden {
		t.Fatalf("cached cert served to denied source: %+v", p)
	}
}

func TestWildcardIdentifier(t *testing.T) {
	e := newEnv(t)
	c := e.mustGet("*.example.com")
	if c.Identifier != "*.example.com" || e.iss.Calls()[0].Identifier != "*.example.com" {
		t.Fatalf("identifier %q", c.Identifier)
	}
	if _, err := os.Stat(filepath.Join(e.dataDir, "certs", "_wildcard.example.com", "current", KeyFile)); err != nil {
		t.Fatal(err)
	}
}

func TestRotate(t *testing.T) {
	e := newEnv(t)
	first := e.mustGet(host)
	if err := e.svc.Rotate(ctx, host); err != nil {
		t.Fatal(err)
	}
	e.idle()
	e.wantCalls(2)
	c := e.mustGet(host)
	if c.Generation != 2 || bytes.Equal(c.KeyPEM, first.KeyPEM) {
		t.Fatal("rotation did not produce a new key")
	}
	// Rotation bypasses the failure backoff but reports failure.
	e.iss.set(func(f *fakeIssuer) { f.errs = []error{&core.ProviderError{Kind: core.ProviderDown}} })
	if err := e.svc.Rotate(ctx, host); err == nil {
		t.Fatal("failed rotation reported success")
	}
	if err := e.svc.Rotate(ctx, host); err != nil {
		t.Fatalf("rotation during backoff: %v", err)
	}
	if c := e.mustGet(host); c.Generation != 3 {
		t.Fatalf("generation %d", c.Generation)
	}
	if err := e.svc.Rotate(ctx, "x.other.net"); err == nil {
		t.Fatal("rotation outside managed zones")
	}
}

func TestVerifyRepairsMissingGeneration(t *testing.T) {
	e := newEnv(t, func(c *core.Config) { c.Direct.RenewFraction = 0.1 })
	e.mustGet(host)
	e.clock.Advance(10 * day)
	e.mustGet(host) // renews: generation 2
	if e.entry(host).Generation != 2 {
		t.Fatal("setup: no second generation")
	}
	gen2 := filepath.Join(e.dataDir, "certs", host, "generations", "000002")
	if err := os.RemoveAll(gen2); err != nil {
		t.Fatal(err)
	}
	e.aud.Reset()

	e.svc = e.newService() // restart
	if err := e.svc.Verify(ctx); err != nil {
		t.Fatal(err)
	}
	en := e.entry(host)
	if en.Generation != 1 || en.CertificateID == "" || en.Provider != "primary" {
		t.Fatalf("entry not repaired: %+v", en)
	}
	if n, err := e.svc.Files().Current(host); err != nil || n != 1 {
		t.Fatalf("current = %d %v", n, err)
	}
	if ev := e.aud.OfType(core.AuditError); len(ev) != 1 || !strings.Contains(ev[0].Detail, "adopted generation 1") {
		t.Fatalf("repair not audited: %+v", ev)
	}
	e.iss.set(func(f *fakeIssuer) { f.failAll = &core.ProviderError{Kind: core.ProviderDown} })
	if c := e.mustGet(host); c.Generation != 1 {
		t.Fatalf("served generation %d after repair", c.Generation)
	}
}

func TestVerifyAdoptsNewerCurrent(t *testing.T) {
	e := newEnv(t)
	e.mustGet(host)
	// Crash between switching "current" and saving the entry.
	k, _ := poolKey(2048)
	now := e.clock.Now()
	_, chain := e.iss.ca.sign(&k.PublicKey, []string{host}, now, now.Add(90*day), false)
	if _, err := e.svc.Files().Write(host, k, chain, now); err != nil {
		t.Fatal(err)
	}
	e.svc = e.newService()
	if err := e.svc.Verify(ctx); err != nil {
		t.Fatal(err)
	}
	if en := e.entry(host); en.Generation != 2 || en.CertificateID != "" {
		t.Fatalf("entry %+v", en)
	}
	if c := e.mustGet(host); c.Generation != 2 {
		t.Fatalf("served %d", c.Generation)
	}
}

func TestVerifyResetsWhenNothingUsable(t *testing.T) {
	e := newEnv(t)
	e.mustGet(host)
	if err := os.RemoveAll(filepath.Join(e.dataDir, "certs", host)); err != nil {
		t.Fatal(err)
	}
	e.svc = e.newService()
	if err := e.svc.Verify(ctx); err != nil {
		t.Fatal(err)
	}
	if en := e.entry(host); en.Generation != 0 || !en.NotAfter.IsZero() {
		t.Fatalf("entry %+v", en)
	}
	c := e.mustGet(host)
	e.wantCalls(2)
	if c.Generation != 1 {
		t.Fatalf("generation %d", c.Generation)
	}
}

func TestVerifyConsistentIsQuiet(t *testing.T) {
	e := newEnv(t)
	e.mustGet(host)
	e.svc = e.newService()
	e.aud.Reset()
	if err := e.svc.Verify(ctx); err != nil {
		t.Fatal(err)
	}
	if len(e.aud.OfType(core.AuditError)) != 0 {
		t.Fatal("consistent entry was repaired")
	}
	if _, ok := e.rec.expiry[host]; !ok {
		t.Fatal("expiry gauge not seeded")
	}
}
