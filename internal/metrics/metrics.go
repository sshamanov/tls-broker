// Package metrics owns the Prometheus registry of the broker and a small
// typed API over it, so that no other package spells a metric name or label.
//
// Other packages receive a Recorder (or declare a narrower interface that
// *Metrics satisfies) and call its methods; tests pass Nop. core defines no
// metrics port, so Recorder lives here.
//
// All metric names start with "tlsbroker_". Label values come from small
// closed sets (modes, outcomes, reasons, provider names from configuration);
// identifiers, IP addresses and usernames are never labels.
package metrics

import (
	"net/http"
	"sort"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	"tls-broker/internal/core"
)

// Outcome of a front-end request, label "outcome" of requests_total.
type Outcome string

const (
	OutcomeOK          Outcome = "ok"           // served / accepted
	OutcomeDenied      Outcome = "denied"       // refused by the gate
	OutcomeRateLimited Outcome = "rate_limited" // refused by the scheduler or a per-source limit
	OutcomeUnavailable Outcome = "unavailable"  // provider down, busy or timed out
	OutcomeError       Outcome = "error"        // bad request or internal error
)

// IssueResult is the result of an issuance, label "result" of issuance_total.
type IssueResult string

const (
	IssueOK     IssueResult = "ok"
	IssueFailed IssueResult = "failed"
)

// Recorder is the API other packages call. *Metrics implements it; Nop is a
// do-nothing implementation for tests and for optional wiring.
type Recorder interface {
	// Request counts one front-end request by mode and outcome.
	Request(mode core.Mode, outcome Outcome)
	// GateDecision counts one gate decision by mode, allow/deny and reason
	// (a core.Reason* value).
	GateDecision(mode core.Mode, allowed bool, reason string)
	// Issuance counts a finished issuance and observes its duration.
	// duration is from admission to the end of the attempt.
	Issuance(provider string, mode core.Mode, class core.PriorityClass, result IssueResult, duration time.Duration)
	// UpstreamError counts a failed upstream CA call by provider and kind.
	UpstreamError(provider string, kind core.ProviderErrorKind)
	// DNS01Present observes one DNS-01 present (record written and
	// propagated); ok false also counts a failure.
	DNS01Present(duration time.Duration, ok bool)
	// DNS01Cleanup counts a failed cleanup of a presented record.
	DNS01CleanupFailure()
	// DirectCacheHit / Miss count direct-mode fetches served from the
	// cache or needing synchronous issuance; DirectRenewal counts a
	// background renewal started.
	DirectCacheHit()
	DirectCacheMiss()
	DirectRenewal(result IssueResult)
	// CertExpiry sets the expiry (unix seconds in the gauge) of a cached
	// direct-mode certificate. Identifier is the only unbounded label in
	// the package and is limited to direct-mode cache entries.
	// Call CertExpiryForget when the entry is removed.
	CertExpiry(identifier string, notAfter time.Time)
	CertExpiryForget(identifier string)
	// AuditWriteFailure counts an audit event that could not be written;
	// wire it to audit.Options.OnError.
	AuditWriteFailure()
}

// Nop implements Recorder and does nothing.
type Nop struct{}

var _ Recorder = Nop{}

func (Nop) Request(core.Mode, Outcome)                                                 {}
func (Nop) GateDecision(core.Mode, bool, string)                                       {}
func (Nop) Issuance(string, core.Mode, core.PriorityClass, IssueResult, time.Duration) {}
func (Nop) UpstreamError(string, core.ProviderErrorKind)                               {}
func (Nop) DNS01Present(time.Duration, bool)                                           {}
func (Nop) DNS01CleanupFailure()                                                       {}
func (Nop) DirectCacheHit()                                                            {}
func (Nop) DirectCacheMiss()                                                           {}
func (Nop) DirectRenewal(IssueResult)                                                  {}
func (Nop) CertExpiry(string, time.Time)                                               {}
func (Nop) CertExpiryForget(string)                                                    {}
func (Nop) AuditWriteFailure()                                                         {}

// Options configure New.
type Options struct {
	// Version is exposed as the build_info label; "" means "dev".
	Version string
	// GoVersion is exposed as the build_info label (runtime.Version()).
	GoVersion string
	// Scheduler supplies the scheduler state at scrape time; nil omits
	// the scheduler metrics. It must be cheap and do no I/O
	// (core.Scheduler.Snapshot).
	Scheduler func() core.SchedulerSnapshot
	// CT supplies the Certificate Transparency inventory at scrape time;
	// nil omits the ct metrics. It must be cheap and do no I/O.
	CT func() CTStats
	// NoRuntime leaves out the Go runtime and process collectors.
	NoRuntime bool
}

// Metrics is the registry plus the typed collectors.
type Metrics struct {
	reg *prometheus.Registry

	requests      *prometheus.CounterVec
	gate          *prometheus.CounterVec
	issuance      *prometheus.CounterVec
	issueDuration *prometheus.HistogramVec
	upstreamErr   *prometheus.CounterVec
	dnsPresent    prometheus.Histogram
	dnsFailures   *prometheus.CounterVec
	directCache   *prometheus.CounterVec
	directRenew   *prometheus.CounterVec
	auditFail     prometheus.Counter

	mu     sync.Mutex
	expiry map[string]time.Time
}

var _ Recorder = (*Metrics)(nil)

const ns = "tlsbroker"

// New builds a registry with every collector registered. It panics only on a
// programming error (duplicate descriptors), which the tests rule out.
func New(o Options) *Metrics {
	m := &Metrics{reg: prometheus.NewRegistry(), expiry: map[string]time.Time{}}
	counter := func(name, help string, labels ...string) *prometheus.CounterVec {
		return prometheus.NewCounterVec(prometheus.CounterOpts{Namespace: ns, Name: name, Help: help}, labels)
	}
	m.requests = counter("requests_total", "Front-end requests by mode and outcome.", "mode", "outcome")
	m.gate = counter("gate_decisions_total", "Gate authorization decisions.", "mode", "decision", "reason")
	m.issuance = counter("issuance_total", "Finished issuance attempts.", "provider", "mode", "class", "result")
	m.issueDuration = prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Namespace: ns, Name: "issuance_duration_seconds",
		Help:    "Time from admission to the end of an issuance attempt.",
		Buckets: []float64{1, 2.5, 5, 10, 20, 30, 60, 120, 240, 600},
	}, []string{"provider", "mode"})
	m.upstreamErr = counter("upstream_errors_total", "Failed upstream CA calls by provider and error kind.", "provider", "kind")
	m.dnsPresent = prometheus.NewHistogram(prometheus.HistogramOpts{
		Namespace: ns, Name: "dns01_present_duration_seconds",
		Help:    "Duration of a DNS-01 present, including propagation.",
		Buckets: []float64{1, 2.5, 5, 10, 20, 30, 60, 120, 240},
	})
	m.dnsFailures = counter("dns01_failures_total", "DNS-01 failures by operation (present, cleanup).", "op")
	m.directCache = counter("direct_cache_total", "Direct-mode fetches by cache result (hit, miss).", "result")
	m.directRenew = counter("direct_renewals_total", "Direct-mode background renewals by result.", "result")
	m.auditFail = prometheus.NewCounter(prometheus.CounterOpts{Namespace: ns, Name: "audit_write_failures_total",
		Help: "Audit events that could not be written."})

	build := prometheus.NewGauge(prometheus.GaugeOpts{Namespace: ns, Name: "build_info",
		Help:        "Build information; the value is always 1.",
		ConstLabels: prometheus.Labels{"version": orDev(o.Version), "go_version": o.GoVersion}})
	build.Set(1)

	m.reg.MustRegister(m.requests, m.gate, m.issuance, m.issueDuration, m.upstreamErr, m.dnsPresent,
		m.dnsFailures, m.directCache, m.directRenew, m.auditFail, build, &expiryCollector{m: m})
	if o.Scheduler != nil {
		m.reg.MustRegister(&schedulerCollector{snap: o.Scheduler})
	}
	if o.CT != nil {
		m.reg.MustRegister(&ctCollector{stats: o.CT})
	}
	if !o.NoRuntime {
		m.reg.MustRegister(collectors.NewGoCollector(), collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}))
	}
	// Make the zero values visible so rate() and absent() work from the
	// first scrape.
	m.auditFail.Add(0)
	m.directCache.WithLabelValues("hit")
	m.directCache.WithLabelValues("miss")
	return m
}

func orDev(s string) string {
	if s == "" {
		return "dev"
	}
	return s
}

// Registry returns the underlying registry (for tests and extra collectors).
func (m *Metrics) Registry() *prometheus.Registry { return m.reg }

// Handler serves /metrics in the Prometheus text format. Restrict it with the
// reverse proxy or network policy (architecture §21).
func (m *Metrics) Handler() http.Handler {
	return promhttp.HandlerFor(m.reg, promhttp.HandlerOpts{ErrorHandling: promhttp.ContinueOnError})
}

func (m *Metrics) Request(mode core.Mode, outcome Outcome) {
	m.requests.WithLabelValues(string(mode), string(outcome)).Inc()
}

func (m *Metrics) GateDecision(mode core.Mode, allowed bool, reason string) {
	d := core.AuditDecisionDeny
	if allowed {
		d = core.AuditDecisionAllow
	}
	m.gate.WithLabelValues(string(mode), d, reason).Inc()
}

func (m *Metrics) Issuance(provider string, mode core.Mode, class core.PriorityClass, result IssueResult, d time.Duration) {
	m.issuance.WithLabelValues(provider, string(mode), class.String(), string(result)).Inc()
	m.issueDuration.WithLabelValues(provider, string(mode)).Observe(d.Seconds())
}

func (m *Metrics) UpstreamError(provider string, kind core.ProviderErrorKind) {
	m.upstreamErr.WithLabelValues(provider, string(kind)).Inc()
}

func (m *Metrics) DNS01Present(d time.Duration, ok bool) {
	m.dnsPresent.Observe(d.Seconds())
	if !ok {
		m.dnsFailures.WithLabelValues("present").Inc()
	}
}

func (m *Metrics) DNS01CleanupFailure() { m.dnsFailures.WithLabelValues("cleanup").Inc() }
func (m *Metrics) DirectCacheHit()      { m.directCache.WithLabelValues("hit").Inc() }
func (m *Metrics) DirectCacheMiss()     { m.directCache.WithLabelValues("miss").Inc() }
func (m *Metrics) DirectRenewal(r IssueResult) {
	m.directRenew.WithLabelValues(string(r)).Inc()
}
func (m *Metrics) AuditWriteFailure() { m.auditFail.Inc() }

func (m *Metrics) CertExpiry(identifier string, notAfter time.Time) {
	m.mu.Lock()
	m.expiry[identifier] = notAfter
	m.mu.Unlock()
}

func (m *Metrics) CertExpiryForget(identifier string) {
	m.mu.Lock()
	delete(m.expiry, identifier)
	m.mu.Unlock()
}

// expiryCollector exports tlsbroker_cert_not_after_timestamp_seconds, one
// series per direct-mode cache entry, from the map the cache keeps current.
type expiryCollector struct{ m *Metrics }

var expiryDesc = prometheus.NewDesc(ns+"_cert_not_after_timestamp_seconds",
	"Expiry (unix time) of the certificate cached for a direct-mode identifier.", []string{"identifier"}, nil)

func (c *expiryCollector) Describe(ch chan<- *prometheus.Desc) { ch <- expiryDesc }

func (c *expiryCollector) Collect(ch chan<- prometheus.Metric) {
	c.m.mu.Lock()
	ids := make([]string, 0, len(c.m.expiry))
	for id := range c.m.expiry {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	vals := make([]float64, len(ids))
	for i, id := range ids {
		vals[i] = float64(c.m.expiry[id].Unix())
	}
	c.m.mu.Unlock()
	for i, id := range ids {
		ch <- prometheus.MustNewConstMetric(expiryDesc, prometheus.GaugeValue, vals[i], id)
	}
}
