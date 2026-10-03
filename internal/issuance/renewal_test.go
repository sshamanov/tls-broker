package issuance_test

import (
	"testing"
	"time"

	"tls-broker/internal/core"
	"tls-broker/internal/core/coretest"
)

func TestRenewalInfoProxiesAndCaches(t *testing.T) {
	e := newEnv(t, nil)
	_, cert := e.issue("acct", "www.example.com")
	e.clock.Advance(2 * time.Hour)

	ri, err := e.eng.RenewalInfo(e.ctx, cert.ARICertID)
	if err != nil {
		t.Fatal(err)
	}
	wantStart := cert.NotBefore.Add(60 * day)
	if !ri.WindowStart.Equal(wantStart) || !ri.WindowEnd.Equal(wantStart.Add(48*time.Hour)) || ri.RetryAfter != 6*time.Hour {
		t.Fatalf("renewal info: %+v", ri)
	}
	// The poll is a lineage observation.
	lin, err := e.st.Lineages().Get(e.ctx, "www.example.com")
	if err != nil || lin.Samples != 1 || lin.ObservedInterval != 2*time.Hour {
		t.Fatalf("lineage: %+v %v", lin, err)
	}
	// Cached until Retry-After, which counts down.
	e.clock.Advance(time.Hour)
	again, err := e.eng.RenewalInfo(e.ctx, cert.ARICertID)
	if err != nil || again.RetryAfter != 5*time.Hour || !again.WindowStart.Equal(ri.WindowStart) {
		t.Fatalf("cached info: %+v %v", again, err)
	}
	if n := e.primary.Stats().Calls[coretest.OpRenewalInfo]; n != 1 {
		t.Fatalf("provider asked %d times, want 1", n)
	}
	e.clock.Advance(5 * time.Hour)
	if _, err := e.eng.RenewalInfo(e.ctx, cert.ARICertID); err != nil {
		t.Fatal(err)
	}
	if n := e.primary.Stats().Calls[coretest.OpRenewalInfo]; n != 2 {
		t.Fatalf("provider asked %d times after expiry, want 2", n)
	}

	_, err = e.eng.RenewalInfo(e.ctx, "unknown.AQID")
	isErr(t, err, core.ErrNotFound)
}

func TestRenewalInfoSynthesizedWithoutARI(t *testing.T) {
	e := newEnv(t, nil)
	e.fallback.SetCaps(core.ProviderCaps{ARI: false})
	e.providers.SetDisabled("primary", true)
	_, cert := e.issue("acct", "www.example.com")
	ri, err := e.eng.RenewalInfo(e.ctx, cert.ARICertID)
	if err != nil {
		t.Fatal(err)
	}
	life := cert.Lifetime()
	wantStart := cert.NotBefore.Add(time.Duration(float64(life) * 2 / 3))
	wantEnd := cert.NotAfter.Add(-(7*day + 12*time.Hour)) // emergency window, default interval
	if !ri.WindowStart.Equal(wantStart) || !ri.WindowEnd.Equal(wantEnd) || ri.RetryAfter != 6*time.Hour {
		t.Fatalf("synthesized window: %+v (want %s..%s)", ri, wantStart, wantEnd)
	}
	if e.fallback.Stats().Calls[coretest.OpRenewalInfo] != 0 {
		t.Fatal("asked a provider without ARI")
	}
	// Renewals of such a certificate still carry no `replaces`.
	e.clock.Advance(61 * day)
	o := e.admit("acct", "www.example.com")
	o = e.waitPrepared(o.ID)
	if o.UpstreamReplaces != "" || o.ARIQualified {
		t.Fatalf("order on a provider without ARI: %+v", o)
	}
}

func TestRenewalInfoProviderDown(t *testing.T) {
	e := newEnv(t, nil)
	_, cert := e.issue("acct", "www.example.com")
	e.primary.Inject(coretest.Fault{Op: coretest.OpRenewalInfo, Err: e.primary.Down()})
	_, err := e.eng.RenewalInfo(e.ctx, cert.ARICertID)
	if pe := core.AsProviderError(err); pe == nil || pe.Kind != core.ProviderDown {
		t.Fatalf("expected provider error, got %v", err)
	}
	// A provider that has forgotten the certificate gets a synthesized window.
	e.primary.ClearFaults()
	e.primary.Inject(coretest.Fault{Op: coretest.OpRenewalInfo, Err: e.primary.Rejected(core.ProblemMalformed, "unknown certificate")})
	ri, err := e.eng.RenewalInfo(e.ctx, cert.ARICertID)
	if err != nil || ri.WindowStart.IsZero() {
		t.Fatalf("synthesized after rejection: %+v %v", ri, err)
	}
	// A provider that is no longer configured: not found.
	e.providers = coretest.NewFakeProviders(e.fallback)
	e.start()
	_, err = e.eng.RenewalInfo(e.ctx, cert.ARICertID)
	isErr(t, err, core.ErrNotFound)
}
