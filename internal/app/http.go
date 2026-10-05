package app

import (
	"context"
	"fmt"
	"net/http"
	"slices"
	"time"

	"tls-broker/internal/core"
	"tls-broker/internal/dnsproxy"
	"tls-broker/internal/httpx"
)

// holdSlack is added to the longest configured hold of a path so the handler
// can still answer with its own timeout response.
const holdSlack = 30 * time.Second

// buildMux mounts every front end. The mux itself never changes; what
// depends on the configuration (real-IP resolution, path timeouts, the DNS
// proxy's zones and limits) is rebuilt by apply.
func (a *App) buildMux() {
	m := http.NewServeMux()
	m.Handle("/acme/", a.acme)
	m.Handle("/dns/", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		a.dnsproxy.Load().ServeHTTP(w, r)
	}))
	m.Handle("/cert/", a.direct.Handler())
	m.Handle("/ui/", a.ui)
	m.Handle("/ui", a.ui)
	m.Handle("/metrics", a.metrics.Handler())
	m.Handle(httpx.HealthPath, a.health)
	m.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		http.Redirect(w, r, "/ui/", http.StatusFound)
	})
	a.mux = m
}

// serveHTTP is the server's handler: the chain built for the current
// configuration.
func (a *App) serveHTTP(w http.ResponseWriter, r *http.Request) {
	(*a.handler.Load()).ServeHTTP(w, r)
}

// apply brings everything that is built from the configuration (rather than
// reading it per call) up to date with cfg.
func (a *App) apply(ctx context.Context, cfg *core.Config) {
	a.applyMu.Lock()
	defer a.applyMu.Unlock()
	prev := a.lastCfg
	a.lastCfg = cfg

	if prev == nil || !slices.Equal(prev.Zones, cfg.Zones) || prev.DNSProxy != cfg.DNSProxy {
		// The DNS proxy takes its zones and limits by value. Rebuilding it
		// resets its in-memory per-source counters.
		a.dnsproxy.Store(dnsproxy.New(dnsproxy.Options{
			Gate: a.gate, Engine: a.dns, Challenges: a.store.Challenges(), Auditor: a.auditor,
			Metrics: a.metrics, Clock: a.clock, Logger: a.log, Zones: cfg.ManagedZones(), Config: cfg.DNSProxy,
		}))
	}
	h := a.chain(cfg)
	a.handler.Store(&h)

	if cfg.LDAP.URL != "" && (prev == nil || prev.LDAP != cfg.LDAP) {
		// One background LDAP check at startup and per change of the LDAP
		// settings, so the status page reports a broken directory without
		// waiting for someone to press "Test LDAP". No periodic re-check:
		// every LDAP login also counts as one.
		via := "startup"
		if prev != nil {
			via = fmt.Sprintf("generation %d", cfg.Generation)
		}
		a.goBG(func(ctx context.Context) { a.ui.CheckLDAP(ctx, via) })
	}

	if prev == nil {
		return
	}
	if prev.Server.ReadTimeout != cfg.Server.ReadTimeout || prev.Server.WriteTimeout != cfg.Server.WriteTimeout {
		a.log.Warn("server.read_timeout/write_timeout changed; they apply after a restart")
	}
	if prev.Audit != cfg.Audit {
		a.log.Warn("audit rotation settings changed; they apply after a restart")
	}
	r53Changed := prev.Route53 != cfg.Route53
	if a.r53 != nil {
		a.r53.update(ctx, cfg.Route53, true)
	}
	if r53Changed || !slices.Equal(prev.Zones, cfg.Zones) {
		go a.verifyZones(a.bgCtx)
	}
}

func (a *App) lastConfig() *core.Config {
	a.applyMu.Lock()
	defer a.applyMu.Unlock()
	return a.lastCfg
}

// chain wraps the mux in the middleware every front end relies on, in the
// order httpx documents: RealIP, RequestID, Recover, AccessLog. RealIP runs
// before RequestID (so a trusted proxy's X-Request-ID is kept) and before the
// access log (so it carries the real source address); Recover runs inside
// RequestID so a panic is logged with the request's ID.
func (a *App) chain(cfg *core.Config) http.Handler {
	acmeHold := max(cfg.Scheduler.AdmitWait, cfg.Scheduler.FinalizeWait) + holdSlack
	h := httpx.PathTimeouts(0,
		httpx.TimeoutRule{Prefix: "/acme/", Timeout: acmeHold},
		httpx.TimeoutRule{Prefix: "/cert/", Timeout: cfg.Direct.IssueTimeout + holdSlack},
		httpx.TimeoutRule{Prefix: "/dns/", Timeout: cfg.DNSProxy.PresentTimeout + holdSlack},
	)(a.mux)
	h = a.readiness(h)
	h = httpx.AccessLog(a.log)(h)
	h = httpx.Recover(a.log)(h)
	h = httpx.RequestID(h)
	return httpx.RealIP(httpx.NewResolver(httpx.Options{
		TrustedProxies: cfg.Server.TrustedProxies, RealIPHeader: cfg.Server.RealIPHeader,
	}))(h)
}

// readiness answers 503 for everything but /healthz and /metrics while the
// broker is not ready (before Run, and once shutdown has begun).
func (a *App) readiness(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if a.ready() || r.URL.Path == "/healthz" || r.URL.Path == "/metrics" {
			next.ServeHTTP(w, r)
			return
		}
		w.Header().Set("Retry-After", "5")
		httpx.WriteProblemStatus(w, http.StatusServiceUnavailable, core.ProblemServerInternal, "the broker is starting or shutting down")
	})
}

func (a *App) ready() bool { return a.isReady.Load() }

// setReady flips readiness for /healthz and for the readiness gate.
func (a *App) setReady(ready bool) {
	a.isReady.Store(ready)
	a.health.SetReady(ready)
}

// startBackground starts the configuration follower, the provider registry
// follower, the CT inventory refresh loop and the housekeeping loop.
func (a *App) startBackground() {
	if a.registry != nil {
		a.goBG(func(ctx context.Context) { a.registry.Follow(ctx, a.cfg) })
	}
	changed, unsubscribe := a.cfg.Subscribe()
	// Catch up with an activation between New and Run.
	if cfg := a.cfg.Current(); cfg != a.lastConfig() {
		a.apply(a.bgCtx, cfg)
	}
	a.goBG(func(ctx context.Context) {
		defer unsubscribe()
		for {
			select {
			case <-ctx.Done():
				return
			case <-changed:
				cfg := a.cfg.Current()
				a.log.Info("configuration changed", "generation", cfg.Generation)
				a.apply(ctx, cfg)
			}
		}
	})
	a.goBG(a.ct.Run)
	iv := a.opts.HousekeepingInterval
	if iv == 0 {
		iv = DefaultHousekeepingInterval
	}
	if iv > 0 {
		a.goBG(func(ctx context.Context) {
			for core.Sleep(ctx, a.clock, iv) == nil {
				a.Housekeep(ctx)
			}
		})
	}
}

func (a *App) goBG(f func(ctx context.Context)) {
	a.bg.Add(1)
	go func() {
		defer a.bg.Done()
		f(a.bgCtx)
	}()
}

// Housekeep runs one maintenance round: expire unfinalized orders and
// compact old ones, remove stale DNS-proxy challenges, prune settled budget
// events and delete expired sessions. Errors are logged. Run calls it every
// HousekeepingInterval; tests may call it directly.
func (a *App) Housekeep(ctx context.Context) {
	if err := a.issuer.Sweep(ctx); err != nil && ctx.Err() == nil {
		a.log.Warn("housekeeping: issuance sweep", "err", err)
	}
	if n, err := a.dnsproxy.Load().Sweep(ctx); err != nil && ctx.Err() == nil {
		a.log.Warn("housekeeping: dns proxy sweep", "err", err, "cleaned", n)
	} else if n > 0 {
		a.log.Info("housekeeping: stale dns proxy challenges removed", "count", n)
	}
	if _, err := a.sched.Prune(ctx); err != nil && ctx.Err() == nil {
		a.log.Warn("housekeeping: budget prune", "err", err)
	}
	if _, err := a.auth.PurgeExpired(ctx); err != nil && ctx.Err() == nil {
		a.log.Warn("housekeeping: session purge", "err", err)
	}
}
