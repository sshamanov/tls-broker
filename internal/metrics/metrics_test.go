package metrics

import (
	"io"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"

	"tls-broker/internal/core"
)

func snap() core.SchedulerSnapshot {
	return core.SchedulerSnapshot{Providers: []core.ProviderSnapshot{
		{Name: "letsencrypt", State: core.ProviderState{Name: "letsencrypt", Health: core.ProviderHealthy}, Open: true,
			SlotsInUse: 2, SlotsTotal: 4, Waiting: 1, Reserved: 3,
			Budgets: []core.BudgetUsage{{Kind: core.BudgetNewOrder, Used: 150, Limit: 200}, {Kind: core.BudgetCertDomain, Key: "example.com", Used: 45, Limit: 40}}},
		{Name: "gts", State: core.ProviderState{Name: "gts", Health: core.ProviderUnavailable}, Open: false, SlotsTotal: 2},
	}}
}

func scrape(t *testing.T, m *Metrics) string {
	t.Helper()
	rec := httptest.NewRecorder()
	m.Handler().ServeHTTP(rec, httptest.NewRequest("GET", "/metrics", nil))
	if rec.Code != 200 {
		t.Fatalf("status %d", rec.Code)
	}
	b, _ := io.ReadAll(rec.Body)
	return string(b)
}

func TestRegistersWithoutConflictAndTwice(t *testing.T) {
	// Two independent instances must not conflict (own registries).
	a := New(Options{Scheduler: snap, Version: "1.2.3", GoVersion: "go1"})
	b := New(Options{Scheduler: snap})
	if _, err := a.Registry().Gather(); err != nil {
		t.Fatal(err)
	}
	if _, err := b.Registry().Gather(); err != nil {
		t.Fatal(err)
	}
	out := scrape(t, a)
	for _, want := range []string{
		`tlsbroker_build_info{go_version="go1",version="1.2.3"} 1`,
		`tlsbroker_audit_write_failures_total 0`,
		`go_goroutines`,
		`tlsbroker_direct_cache_total{result="hit"} 0`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q", want)
		}
	}
	if !strings.Contains(scrape(t, b), `version="dev"`) {
		t.Error("default version")
	}
}

func TestCounters(t *testing.T) {
	m := New(Options{NoRuntime: true})
	m.Request(core.ModeACME, OutcomeOK)
	m.Request(core.ModeACME, OutcomeOK)
	m.Request(core.ModeDirect, OutcomeDenied)
	m.GateDecision(core.ModeACME, false, core.ReasonDNSMismatch)
	m.GateDecision(core.ModeACME, true, core.ReasonIPGrant)
	m.Issuance("letsencrypt", core.ModeACME, core.ClassARIRenewal, IssueOK, 12*time.Second)
	m.Issuance("letsencrypt", core.ModeACME, core.ClassARIRenewal, IssueFailed, 3*time.Second)
	m.UpstreamError("letsencrypt", core.ProviderRateLimited)
	m.DNS01Present(7*time.Second, true)
	m.DNS01Present(130*time.Second, false)
	m.DNS01CleanupFailure()
	m.DirectCacheHit()
	m.DirectCacheHit()
	m.DirectCacheMiss()
	m.DirectRenewal(IssueOK)
	m.AuditWriteFailure()

	check := func(name string, got, want float64) {
		t.Helper()
		if got != want {
			t.Errorf("%s = %v, want %v", name, got, want)
		}
	}
	check("requests acme ok", testutil.ToFloat64(m.requests.WithLabelValues("acme", "ok")), 2)
	check("requests direct denied", testutil.ToFloat64(m.requests.WithLabelValues("direct", "denied")), 1)
	check("gate deny", testutil.ToFloat64(m.gate.WithLabelValues("acme", "deny", "dns_mismatch")), 1)
	check("gate allow", testutil.ToFloat64(m.gate.WithLabelValues("acme", "allow", "ip_grant")), 1)
	check("issuance ok", testutil.ToFloat64(m.issuance.WithLabelValues("letsencrypt", "acme", "ari_renewal", "ok")), 1)
	check("issuance failed", testutil.ToFloat64(m.issuance.WithLabelValues("letsencrypt", "acme", "ari_renewal", "failed")), 1)
	check("upstream", testutil.ToFloat64(m.upstreamErr.WithLabelValues("letsencrypt", "rate_limited")), 1)
	check("dns present failures", testutil.ToFloat64(m.dnsFailures.WithLabelValues("present")), 1)
	check("dns cleanup failures", testutil.ToFloat64(m.dnsFailures.WithLabelValues("cleanup")), 1)
	check("cache hit", testutil.ToFloat64(m.directCache.WithLabelValues("hit")), 2)
	check("cache miss", testutil.ToFloat64(m.directCache.WithLabelValues("miss")), 1)
	check("renewals", testutil.ToFloat64(m.directRenew.WithLabelValues("ok")), 1)
	check("audit", testutil.ToFloat64(m.auditFail), 1)

	out := scrape(t, m)
	for _, want := range []string{
		`tlsbroker_issuance_duration_seconds_count{mode="acme",provider="letsencrypt"} 2`,
		`tlsbroker_issuance_duration_seconds_sum{mode="acme",provider="letsencrypt"} 15`,
		`tlsbroker_dns01_present_duration_seconds_count 2`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in\n%s", want, out)
		}
	}
}

func TestSchedulerCollector(t *testing.T) {
	m := New(Options{Scheduler: snap, NoRuntime: true})
	out := scrape(t, m)
	for _, want := range []string{
		`tlsbroker_scheduler_slots_in_use{provider="letsencrypt"} 2`,
		`tlsbroker_scheduler_slots_total{provider="letsencrypt"} 4`,
		`tlsbroker_scheduler_waiters{provider="letsencrypt"} 1`,
		`tlsbroker_scheduler_reservations{provider="letsencrypt"} 3`,
		`tlsbroker_scheduler_circuit_open{provider="letsencrypt"} 0`,
		`tlsbroker_scheduler_circuit_open{provider="gts"} 1`,
		`tlsbroker_scheduler_provider_state{provider="gts",state="down"} 1`,
		`tlsbroker_scheduler_provider_state{provider="gts",state="healthy"} 0`,
		`tlsbroker_scheduler_provider_state{provider="letsencrypt",state="healthy"} 1`,
		`tlsbroker_scheduler_budget_remaining{key="",kind="new_order",provider="letsencrypt"} 50`,
		`tlsbroker_scheduler_budget_remaining{key="example.com",kind="cert_domain",provider="letsencrypt"} 0`,
		`tlsbroker_scheduler_budget_limit{key="example.com",kind="cert_domain",provider="letsencrypt"} 40`,
		`tlsbroker_scheduler_budget_used{key="example.com",kind="cert_domain",provider="letsencrypt"} 45`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in\n%s", want, out)
		}
	}
	// No scheduler configured: no scheduler series, no error.
	if strings.Contains(scrape(t, New(Options{NoRuntime: true})), "scheduler_") {
		t.Error("scheduler metrics without a scheduler")
	}
}

func TestSchedulerCollectorFollowsState(t *testing.T) {
	s := snap()
	m := New(Options{Scheduler: func() core.SchedulerSnapshot { return s }, NoRuntime: true})
	s.Providers[1].Open = true
	s.Providers[1].State.Health = core.ProviderHealthy
	if !strings.Contains(scrape(t, m), `tlsbroker_scheduler_circuit_open{provider="gts"} 0`) {
		t.Error("snapshot is read at scrape time")
	}
}

func TestCertExpiry(t *testing.T) {
	m := New(Options{NoRuntime: true})
	exp := time.Date(2026, 12, 1, 0, 0, 0, 0, time.UTC)
	m.CertExpiry("a.example.com", exp)
	m.CertExpiry("b.example.com", exp.Add(time.Hour))
	out := scrape(t, m)
	if !strings.Contains(out, `tlsbroker_cert_not_after_timestamp_seconds{identifier="a.example.com"} 1.7960832e+09`) {
		t.Errorf("missing a:\n%s", out)
	}
	m.CertExpiryForget("a.example.com")
	out = scrape(t, m)
	if strings.Contains(out, "a.example.com") || !strings.Contains(out, "b.example.com") {
		t.Errorf("forget:\n%s", out)
	}
}

func TestNop(t *testing.T) {
	var r Recorder = Nop{}
	r.Request(core.ModeACME, OutcomeOK)
	r.AuditWriteFailure()
}

func TestCTCollector(t *testing.T) {
	ok := time.Date(2026, 10, 5, 12, 0, 0, 0, time.UTC)
	stats := CTStats{States: map[string]int{"ok": 30, "expired": 1, "overdue": 0}, UnexpectedCA: 2,
		Zones: []CTZone{{Zone: "example.com", LastSuccess: ok, OK: true}, {Zone: "example.org"}}}
	m := New(Options{CT: func() CTStats { return stats }, NoRuntime: true})
	out := scrape(t, m)
	for _, want := range []string{
		`tlsbroker_ct_certificates{state="ok"} 30`,
		`tlsbroker_ct_certificates{state="overdue"} 0`,
		`tlsbroker_ct_unexpected_ca_certificates 2`,
		`tlsbroker_ct_last_success_timestamp_seconds{zone="example.com"} 1.7912016e+09`,
		`tlsbroker_ct_last_success_timestamp_seconds{zone="example.org"} 0`,
		`tlsbroker_ct_zone_up{zone="example.com"} 1`,
		`tlsbroker_ct_zone_up{zone="example.org"} 0`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %s in\n%s", want, out)
		}
	}
	if strings.Contains(scrape(t, New(Options{NoRuntime: true})), "tlsbroker_ct_") {
		t.Error("ct metrics without a source")
	}
}
