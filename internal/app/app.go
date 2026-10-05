// Package app wires every package of the broker into one running process:
// it opens the stores, builds the engines and front ends, runs startup
// recovery (architecture §20), serves HTTP and shuts everything down in
// order. It is the only package that knows the concrete types; nothing
// imports it except cmd/tls-broker and the end-to-end tests.
//
// Startup order (New): data directory → SQLite → secrets → configuration
// generations → metrics and audit → providers → DoH resolver → gate → CT
// inventory (empty) → scheduler → Route53 + DNS-01 engine (zones verified, warn only) →
// DNSEngine.Reconcile → issuance engine Recover → direct cache Verify →
// listener. Run then marks the broker ready, serves, runs housekeeping and
// the CT inventory refresh (first one at once), follows configuration changes until its context ends, and finally drains
// and closes everything (see Close).
package app

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"tls-broker/internal/acmesrv"
	"tls-broker/internal/audit"
	"tls-broker/internal/auth"
	"tls-broker/internal/config"
	"tls-broker/internal/core"
	"tls-broker/internal/ctlog"
	"tls-broker/internal/direct"
	"tls-broker/internal/dns01"
	"tls-broker/internal/dnsproxy"
	"tls-broker/internal/doh"
	"tls-broker/internal/gate"
	"tls-broker/internal/guide"
	"tls-broker/internal/httpx"
	"tls-broker/internal/issuance"
	"tls-broker/internal/metrics"
	"tls-broker/internal/sched"
	"tls-broker/internal/store"
	"tls-broker/internal/ui"
	"tls-broker/internal/upstream"
	"tls-broker/internal/version"
)

// DefaultHousekeepingInterval is how often the periodic maintenance round
// runs (order expiry, stale DNS-proxy challenges, budget pruning, expired
// sessions) when Options.HousekeepingInterval is zero.
const DefaultHousekeepingInterval = time.Minute

// zoneCheckTimeout bounds the Route53 zone verification at startup and after
// a configuration change.
const zoneCheckTimeout = 30 * time.Second

// MockedDNSBanner is shown on every UI page while TLS_BROKER_DOH_ENDPOINTS
// replaces the public resolvers.
const MockedDNSBanner = "DNS gate is mocked: public DNS lookups go to TLS_BROKER_DOH_ENDPOINTS instead of Cloudflare/Google. Development only."

// Options inject replacements for the external dependencies. The zero value
// is production: every field is optional. The end-to-end tests set the fakes.
type Options struct {
	// Logger receives all logs; nil means slog.Default().
	Logger *slog.Logger
	// Clock drives every package; nil means core.SystemClock. The
	// housekeeping loop sleeps on it too (Housekeep runs one round
	// directly).
	Clock core.Clock
	// Providers replaces the upstream ACME registry built from the
	// configuration (for example coretest.NewFakeProviders(fakeCA)). The
	// configuration must still list providers with the same names: the
	// scheduler, gate and issuance engine read limits and order from it.
	Providers core.Providers
	// UpstreamRootCAs replaces the system roots for the real upstream
	// adapter (a Pebble test CA). Ignored when Providers is set.
	UpstreamRootCAs *x509.CertPool
	// Route53 replaces the AWS client (for example dns01.NewFakeRoute53).
	// Nil builds the real client from the configuration and rebuilds it
	// when the region or credential secret names change.
	Route53 dns01.Route53API
	// Resolver replaces the DoH resolver (for example
	// coretest.NewFakeResolver()).
	Resolver core.Resolver
	// Directory replaces the LDAP directory used for logins (for example
	// coretest.NewFakeDirectory()).
	Directory core.Directory
	// LDAPTester replaces the LDAP connectivity test used by configuration
	// activation and the UI. Nil uses the real LDAP client.
	LDAPTester core.LDAPTester
	// Listener replaces net.Listen on the TLS_BROKER_LISTEN address (for
	// example a listener on 127.0.0.1:0).
	Listener net.Listener
	// NewDirectKey generates direct-mode private keys; nil uses
	// rsa.GenerateKey. Tests inject pre-generated keys.
	NewDirectKey func(bits int) (*rsa.PrivateKey, error)
	// HousekeepingInterval is the period of the maintenance round; zero
	// means DefaultHousekeepingInterval, negative disables the loop.
	HousekeepingInterval time.Duration
	// CTSource replaces the Certificate Transparency source (SSLMate Cert
	// Spotter) of the CT inventory, for example ctlog.NewFakeSource(0).
	// With a replacement the inventory does not pause between requests.
	CTSource ctlog.Source
	// Docs is the user guide for the UI's Documentation reader; nil reads
	// guide.DefaultDir, where the image ships docs/guide.md. Tests and
	// development pass os.DirFS("docs").
	Docs fs.FS
}

// App is the wired broker.
type App struct {
	env   config.Env
	opts  Options
	log   *slog.Logger
	clock core.Clock

	store     *store.Store
	secrets   *config.FileSecrets
	cfg       *config.Store
	metrics   *metrics.Metrics
	auditLog  *audit.Log
	auditor   core.Auditor
	providers core.Providers
	registry  *upstream.Registry
	resolver  core.Resolver
	gate      *gate.Gate
	sched     *sched.Scheduler
	r53       *route53Switch
	dnsEngine *dns01.Engine
	dns       core.DNSEngine
	issuer    *issuance.Engine
	direct    *direct.Service
	ct        *ctlog.Inventory
	acme      *acmesrv.Server
	auth      *auth.Service
	ui        *ui.Handler
	health    *httpx.Health
	isReady   atomic.Bool
	banners   []string

	mux      *http.ServeMux
	dnsproxy atomic.Pointer[dnsproxy.Handler]
	handler  atomic.Pointer[http.Handler]
	srv      *http.Server
	ln       net.Listener

	// lastCfg is the configuration the HTTP chain and Route53 client were
	// last built for (guarded by applyMu).
	applyMu sync.Mutex
	lastCfg *core.Config

	bgCtx    context.Context
	bgCancel context.CancelFunc
	bg       sync.WaitGroup

	closeOnce sync.Once
	closeErr  error
}

// New builds the whole broker and runs startup recovery. On success the
// listener is bound but nothing is served until Run. On error everything
// opened so far is closed again.
func New(ctx context.Context, env config.Env, opts Options) (_ *App, err error) {
	a := &App{env: env, opts: opts, log: opts.Logger, clock: opts.Clock}
	if a.log == nil {
		a.log = slog.Default()
	}
	if a.clock == nil {
		a.clock = core.SystemClock{}
	}
	a.bgCtx, a.bgCancel = context.WithCancel(context.Background())
	defer func() {
		if err != nil {
			a.abort()
		}
	}()
	a.log.Info("starting tls-broker", "version", version.String(), "go", runtime.Version(),
		"data_dir", env.DataDir, "listen", env.Listen)

	if err := os.MkdirAll(env.DataDir, 0o750); err != nil {
		return nil, fmt.Errorf("data directory %s: %w", env.DataDir, err)
	}
	if a.store, err = store.Open(filepath.Join(env.DataDir, "state.db")); err != nil {
		return nil, fmt.Errorf("open database: %w", err)
	}
	if v, err := a.store.SchemaVersion(ctx); err == nil {
		a.log.Info("database open", "path", filepath.Join(env.DataDir, "state.db"), "schema", v)
	}
	if a.secrets, err = config.NewFileSecrets(env.DataDir); err != nil {
		return nil, fmt.Errorf("open secrets: %w", err)
	}
	// The LDAP client needs the configuration source, and the
	// configuration store needs the LDAP tester: break the cycle with a
	// forwarding tester filled in right after.
	tester := &lazyLDAPTester{}
	if a.cfg, err = config.Open(config.Options{Env: env, Secrets: a.secrets, LDAP: tester, Logger: a.log}); err != nil {
		return nil, fmt.Errorf("open configuration: %w", err)
	}
	cfg := a.cfg.Current()
	a.log.Info("configuration loaded", "generation", cfg.Generation, "zones", len(cfg.Zones),
		"providers", len(cfg.EnabledProviders()), "ldap", cfg.LDAP.URL != "")
	var directory core.Directory
	if opts.LDAPTester != nil {
		tester.set(opts.LDAPTester)
	}
	if opts.Directory != nil {
		directory = opts.Directory
	}
	if directory == nil || opts.LDAPTester == nil {
		ldap := auth.NewLDAP(a.cfg, a.secrets)
		if directory == nil {
			directory = ldap
		}
		if opts.LDAPTester == nil {
			tester.set(ldap)
		}
	}

	a.metrics = metrics.New(metrics.Options{
		Version: version.String(), GoVersion: runtime.Version(),
		Scheduler: func() core.SchedulerSnapshot {
			if a.sched == nil {
				return core.SchedulerSnapshot{}
			}
			return a.sched.Snapshot()
		},
		CT: a.ctStats,
	})
	if a.auditLog, err = audit.Open(audit.Options{
		Dir: filepath.Join(env.DataDir, "audit"), Clock: a.clock,
		MaxFileBytes: cfg.Audit.MaxFileBytes, MaxFiles: cfg.Audit.MaxFiles,
		OnError: func(error) { a.metrics.AuditWriteFailure() }, Logger: a.log,
	}); err != nil {
		return nil, fmt.Errorf("open audit log: %w", err)
	}
	a.auditor = &issueMetrics{next: a.auditLog, m: a.metrics, orders: a.store.Orders(), clock: a.clock}

	providers := opts.Providers
	if providers == nil {
		if a.registry, err = upstream.NewRegistry(cfg, upstream.Options{Secrets: a.secrets, Clock: a.clock, RootCAs: opts.UpstreamRootCAs}); err != nil {
			return nil, fmt.Errorf("upstream providers: %w", err)
		}
		providers = a.registry
	}
	a.providers = &meteredProviders{next: providers, m: a.metrics}

	a.resolver = opts.Resolver
	if a.resolver == nil {
		var dohOpts []doh.Option
		if len(env.DoHEndpoints) > 0 {
			dohOpts = append(dohOpts, doh.WithEndpoints(env.DoHEndpoints...))
			a.log.Warn("!!! DNS GATE IS MOCKED: TLS_BROKER_DOH_ENDPOINTS replaces the public DoH resolvers; development only !!!",
				"endpoints", strings.Join(env.DoHEndpoints, ","))
			a.banners = append(a.banners, MockedDNSBanner)
		}
		a.resolver = doh.New(a.cfg, dohOpts...)
	}
	a.gate = gate.New(a.cfg, a.store.Grants(), a.resolver, a.providers)
	a.ct = newCTInventory(a.cfg, a.resolver, a.clock, a.log, opts.CTSource)

	if a.sched, err = sched.New(ctx, sched.Options{
		Config: a.cfg, Budgets: a.store.Budgets(), States: a.store.ProviderStates(),
		Clock: a.clock, Auditor: a.auditor, Logger: a.log,
	}); err != nil {
		return nil, fmt.Errorf("scheduler: %w", err)
	}

	api := opts.Route53
	if api == nil {
		a.r53 = newRoute53Switch(a.secrets, a.clock, a.log)
		a.r53.update(ctx, cfg.Route53, false)
		api = a.r53
	}
	if a.dnsEngine, err = dns01.New(dns01.Options{
		Config: a.cfg, Store: a.store.Challenges(), Resolver: a.resolver, API: api, Clock: a.clock, Logger: a.log,
	}); err != nil {
		return nil, fmt.Errorf("dns-01 engine: %w", err)
	}
	a.dns = &meteredDNS{next: a.dnsEngine, m: a.metrics, clock: a.clock}
	a.verifyZones(ctx)
	if err := a.dnsEngine.Reconcile(ctx); err != nil {
		// Challenges that could not be repaired stay non-terminal; the
		// next start (or their owner's cleanup) tries again.
		a.log.Warn("dns-01 reconcile incomplete", "err", err)
	}

	if a.issuer, err = issuance.New(issuance.Options{
		Config: a.cfg, Clock: a.clock, Orders: a.store.Orders(), Certs: a.store.Certificates(),
		Lineages: a.store.Lineages(), Providers: a.providers, DNS: a.dns, Scheduler: a.sched,
		Gate: a.gate, Auditor: a.auditor, Logger: a.log,
	}); err != nil {
		return nil, fmt.Errorf("issuance engine: %w", err)
	}
	if err := a.issuer.Recover(ctx); err != nil {
		return nil, fmt.Errorf("recover orders: %w", err)
	}

	if a.direct, err = direct.New(direct.Options{
		Config: a.cfg, Issuer: a.issuer, Gate: a.gate, Entries: a.store.Direct(), Lineages: a.store.Lineages(),
		Certificates: a.store.Certificates(), Auditor: a.auditor, Metrics: a.metrics, Clock: a.clock,
		Logger: a.log, NewKey: opts.NewDirectKey,
	}); err != nil {
		return nil, fmt.Errorf("direct cache: %w", err)
	}
	if err := a.direct.Verify(ctx); err != nil {
		return nil, fmt.Errorf("verify direct cache: %w", err)
	}

	if a.acme, err = acmesrv.New(acmesrv.Options{
		Config: a.cfg, Accounts: a.store.Accounts(), Orders: a.store.Orders(), Certificates: a.store.Certificates(),
		Gate: a.gate, Issuer: a.issuer, Auditor: a.auditor, Metrics: a.metrics, Clock: a.clock, Logger: a.log,
	}); err != nil {
		return nil, fmt.Errorf("acme server: %w", err)
	}
	a.auth = auth.New(auth.Deps{
		Config: a.cfg, Users: a.store.Users(), Sessions: a.store.Sessions(), Directory: directory,
		Clock: a.clock, Audit: a.auditor,
	})
	docs := opts.Docs
	if docs == nil {
		docs = os.DirFS(guide.DefaultDir)
	}
	if a.ui, err = ui.New(ui.Deps{
		Auth: a.auth, Config: a.cfg, Admin: a.cfg, Secrets: a.secrets, LDAP: tester, CAA: a.gate,
		Providers: a.providers, Scheduler: a.sched, Audit: a.auditLog, Auditor: a.auditor,
		Users: a.store.Users(), Grants: a.store.Grants(), Certs: a.store.Certificates(), Orders: a.store.Orders(),
		Direct: a.store.Direct(), Lineages: a.store.Lineages(), Clock: a.clock, Rotator: a.direct,
		Zones: zoneStatusSource{a.dnsEngine}, Inventory: a.ct, Banners: a.banners, Docs: docs, Logger: a.log,
	}); err != nil {
		return nil, fmt.Errorf("web ui: %w", err)
	}

	a.health = &httpx.Health{Ping: func(ctx context.Context) error {
		_, err := a.store.SchemaVersion(ctx)
		return err
	}}
	a.buildMux()
	a.apply(ctx, cfg)

	a.ln = opts.Listener
	if a.ln == nil {
		if a.ln, err = net.Listen("tcp", env.Listen); err != nil {
			return nil, fmt.Errorf("listen on %s (%s): %w", env.Listen, config.EnvListen, err)
		}
	}
	a.srv = &http.Server{
		Handler:           http.HandlerFunc(a.serveHTTP),
		ReadHeaderTimeout: min(cfg.Server.ReadTimeout, 10*time.Second),
		ReadTimeout:       cfg.Server.ReadTimeout,
		WriteTimeout:      cfg.Server.WriteTimeout,
		IdleTimeout:       2 * time.Minute,
		ErrorLog:          slog.NewLogLogger(a.log.Handler(), slog.LevelWarn),
	}
	a.log.Info("startup recovery complete", "addr", a.ln.Addr().String())
	return a, nil
}

// Addr is the address the broker listens on.
func (a *App) Addr() net.Addr { return a.ln.Addr() }

// Handler is the complete HTTP handler (middleware and every mount), for
// in-process tests that do not want a socket. It answers 503 except for
// /healthz and /metrics until Run has marked the broker ready.
func (a *App) Handler() http.Handler { return http.HandlerFunc(a.serveHTTP) }

// Store is the SQLite store (for tests and the CLI helpers).
func (a *App) Store() *store.Store { return a.store }

// Config is the configuration generation store (core.ConfigSource and
// core.ConfigAdmin).
func (a *App) Config() *config.Store { return a.cfg }

// Secrets is the secret store under <data>/secrets.
func (a *App) Secrets() *config.FileSecrets { return a.secrets }

// Run marks the broker ready, serves HTTP, runs housekeeping and follows
// configuration changes until ctx ends or the server fails, then calls
// Close. It returns the server error, if any, joined with Close's.
func (a *App) Run(ctx context.Context) error {
	a.startBackground()
	serveErr := make(chan error, 1)
	go func() { serveErr <- a.srv.Serve(a.ln) }()
	a.setReady(true)
	a.log.Info("tls-broker ready", "addr", a.ln.Addr().String())

	var err error
	select {
	case <-ctx.Done():
		a.log.Info("shutdown requested")
	case err = <-serveErr:
		if errors.Is(err, http.ErrServerClosed) {
			err = nil
		} else {
			a.log.Error("http server failed", "err", err)
		}
	}
	return errors.Join(err, a.Close())
}

// Close drains and stops the broker: readiness off, stop accepting and wait
// for in-flight requests up to server.shutdown_grace, stop background loops,
// let the issuance engine finish (interrupted work is left for the next
// Recover), stop direct-mode jobs, the DNS-01 engine and the scheduler, and
// close the audit log and the database. Idempotent.
func (a *App) Close() error {
	a.closeOnce.Do(func() {
		grace := a.cfg.Current().Server.ShutdownGrace
		if grace <= 0 {
			grace = core.DefaultConfig().Server.ShutdownGrace
		}
		ctx, cancel := context.WithTimeout(context.Background(), grace)
		defer cancel()
		a.setReady(false)
		var errs []error
		if err := a.srv.Shutdown(ctx); err != nil {
			errs = append(errs, fmt.Errorf("http shutdown: %w", err))
			_ = a.srv.Close()
		}
		a.bgCancel()
		a.bg.Wait()
		if err := a.issuer.Close(ctx); err != nil {
			errs = append(errs, fmt.Errorf("issuance: %w", err))
		}
		a.direct.Close()
		if err := a.dnsEngine.Close(ctx); err != nil {
			errs = append(errs, fmt.Errorf("dns-01: %w", err))
		}
		a.closeRest(&errs)
		a.closeErr = errors.Join(errs...)
		a.log.Info("tls-broker stopped")
	})
	return a.closeErr
}

// abort closes whatever New opened before it failed.
func (a *App) abort() {
	a.bgCancel()
	a.bg.Wait()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if a.issuer != nil {
		_ = a.issuer.Close(ctx)
	}
	if a.direct != nil {
		a.direct.Close()
	}
	if a.dnsEngine != nil {
		_ = a.dnsEngine.Close(ctx)
	}
	if a.ln != nil && a.opts.Listener == nil {
		_ = a.ln.Close()
	}
	var errs []error
	a.closeRest(&errs)
}

func (a *App) closeRest(errs *[]error) {
	if a.sched != nil {
		if err := a.sched.Close(); err != nil {
			*errs = append(*errs, fmt.Errorf("scheduler: %w", err))
		}
	}
	if a.auditLog != nil {
		if err := a.auditLog.Close(); err != nil {
			*errs = append(*errs, fmt.Errorf("audit log: %w", err))
		}
	}
	if a.store != nil {
		if err := a.store.Close(); err != nil {
			*errs = append(*errs, fmt.Errorf("database: %w", err))
		}
	}
}

// verifyZones discovers the hosted zone IDs that are not configured and
// checks the managed zones against Route53. A failure is only a warning: on
// first start AWS is usually not configured yet.
func (a *App) verifyZones(ctx context.Context) {
	if len(a.cfg.Current().Zones) == 0 {
		return
	}
	ctx, cancel := context.WithTimeout(ctx, zoneCheckTimeout)
	defer cancel()
	err := a.dnsEngine.VerifyZones(ctx)
	for _, z := range a.dnsEngine.ZoneStatuses() {
		if z.Resolved {
			a.log.Info("route53 hosted zone discovered by name", "zone", z.Name, "hosted_zone_id", z.HostedZoneID)
		}
	}
	if err != nil {
		a.log.Warn("route53 zone check failed; DNS-01 will fail until Route53 is reachable and the zones match", "err", err)
		return
	}
	a.log.Info("route53 zones verified", "zones", len(a.cfg.Current().Zones))
}

// newCTInventory builds the Certificate Transparency inventory on the given
// source, or on Cert Spotter with a polite pause between requests.
func newCTInventory(cfg core.ConfigSource, res core.Resolver, clock core.Clock, log *slog.Logger, src ctlog.Source) *ctlog.Inventory {
	pace := time.Duration(0)
	if src == nil {
		src = &ctlog.CertSpotter{UserAgent: "tls-broker/" + version.String()}
		pace = ctlog.DefaultPace
	}
	return ctlog.New(ctlog.Options{Config: cfg, Source: src, Resolver: res, Clock: clock, Logger: log, Pace: pace})
}

// ctStates are the states the ct metrics always list.
var ctStates = []ctlog.State{ctlog.StateOK, ctlog.StateDue, ctlog.StateOverdue, ctlog.StateExpired, ctlog.StateReplaced, ctlog.StateRevoked}

// ctStats feeds the ct metrics at scrape time.
func (a *App) ctStats() metrics.CTStats {
	var st metrics.CTStats
	if a.ct == nil {
		return st
	}
	snap := a.ct.Snapshot()
	if !snap.Enabled {
		return st
	}
	rep := ctlog.Analyze(snap, a.clock.Now(), nil)
	st.States = map[string]int{}
	for _, s := range ctStates {
		st.States[string(s)] = rep.Counts[s]
	}
	st.UnexpectedCA = rep.Unexpected
	for _, z := range snap.Zones {
		st.Zones = append(st.Zones, metrics.CTZone{Zone: z.Zone, LastSuccess: z.LastSuccess, OK: !z.LastAttempt.IsZero() && z.Err == ""})
	}
	return st
}

// zoneStatusSource adapts the DNS-01 engine to ui.ZoneStatusSource.
type zoneStatusSource struct{ eng *dns01.Engine }

func (s zoneStatusSource) ZoneStatuses() []ui.ZoneStatus {
	src := s.eng.ZoneStatuses()
	out := make([]ui.ZoneStatus, 0, len(src))
	for _, z := range src {
		out = append(out, ui.ZoneStatus(z))
	}
	return out
}

// lazyLDAPTester forwards to the tester set after construction.
type lazyLDAPTester struct {
	mu sync.Mutex
	t  core.LDAPTester
}

func (l *lazyLDAPTester) set(t core.LDAPTester) {
	l.mu.Lock()
	l.t = t
	l.mu.Unlock()
}

func (l *lazyLDAPTester) TestLDAP(ctx context.Context, cfg core.LDAPConfig) error {
	l.mu.Lock()
	t := l.t
	l.mu.Unlock()
	if t == nil {
		return errors.New("LDAP tester not ready")
	}
	return t.TestLDAP(ctx, cfg)
}
