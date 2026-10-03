package app

import (
	"bytes"
	"context"
	"crypto/rsa"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"tls-broker/internal/config"
	"tls-broker/internal/core"
	"tls-broker/internal/core/coretest"
	"tls-broker/internal/dns01"
)

const testYAML = `server:
  external_url: http://broker.test
  trusted_proxies: [127.0.0.1]
  real_ip_header: X-Real-IP
zones:
  - name: example.com
    hosted_zone_id: Z1EXAMPLE
providers:
  - name: primary
    directory_url: https://primary.test/directory
    caa_issuers: [primary.test]
    account_uri_honoured: true
    ari: true
    ari_exempt: true
`

var testKey = sync.OnceValue(coretest.GenRSAKey)

type okTester struct{}

func (okTester) TestLDAP(context.Context, core.LDAPConfig) error { return nil }

type fixture struct {
	env      config.Env
	clock    *coretest.FakeClock
	ca       *coretest.FakeCA
	r53      *dns01.FakeRoute53
	resolver *coretest.FakeResolver
	dir      *coretest.FakeDirectory
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	env := config.DefaultEnv()
	env.DataDir = t.TempDir()
	env.Listen = "127.0.0.1:0"
	env.Bootstrap = core.BootstrapConfig{Admins: []string{"alice"}, LocalAdminUser: "root", LocalAdminPassword: "rootpw"}
	clock := coretest.NewFakeClock(coretest.At(2026, 10, 3, 12))
	f := &fixture{env: env, clock: clock, ca: coretest.NewFakeCA("primary", clock),
		r53: dns01.NewFakeRoute53(clock), resolver: coretest.NewFakeResolver(), dir: coretest.NewFakeDirectory()}
	f.r53.AddZone("Z1EXAMPLE", "example.com")
	// The CA validates against, and the resolver sees, Route53's public view.
	f.ca.SetTXTLookup(f.r53.LookupTXT)
	f.dir.SetUser("bob", "bob-pw")
	return f
}

func (f *fixture) options(t *testing.T) Options {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	return Options{
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil)), Clock: f.clock,
		Providers: coretest.NewFakeProviders(f.ca), Route53: f.r53, Resolver: f.r53.Resolver(f.resolver),
		Directory: f.dir, LDAPTester: okTester{}, Listener: ln,
		NewDirectKey: func(int) (*rsa.PrivateKey, error) { return testKey(), nil },
	}
}

// running is a broker served by Run in the background.
type running struct {
	t      *testing.T
	app    *App
	base   string
	client *http.Client
	cancel context.CancelFunc
	done   chan error
}

func start(t *testing.T, env config.Env, opts Options) *running {
	t.Helper()
	a, err := New(context.Background(), env, opts)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	r := &running{t: t, app: a, base: "http://" + a.Addr().String(), cancel: cancel, done: make(chan error, 1),
		client: &http.Client{Transport: &http.Transport{}, CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		}}}
	go func() { r.done <- a.Run(ctx) }()
	deadline := time.Now().Add(5 * time.Second)
	for {
		if resp, err := r.client.Get(r.base + "/healthz"); err == nil {
			resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				break
			}
		}
		if time.Now().After(deadline) {
			t.Fatal("broker did not become ready")
		}
		time.Sleep(10 * time.Millisecond)
	}
	return r
}

func (r *running) stop() {
	r.t.Helper()
	r.cancel()
	select {
	case err := <-r.done:
		if err != nil {
			r.t.Fatalf("Run: %v", err)
		}
	case <-time.After(30 * time.Second):
		r.t.Fatal("Run did not return")
	}
	r.client.CloseIdleConnections()
}

func (r *running) get(path string, hdr ...string) (int, http.Header, string) {
	r.t.Helper()
	req, _ := http.NewRequest(http.MethodGet, r.base+path, nil)
	for i := 0; i+1 < len(hdr); i += 2 {
		req.Header.Set(hdr[i], hdr[i+1])
	}
	resp, err := r.client.Do(req)
	if err != nil {
		r.t.Fatalf("GET %s: %v", path, err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, resp.Header, string(b)
}

// noLeaks waits for the goroutine count to fall back to the baseline.
func noLeaks(t *testing.T, before int) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for runtime.NumGoroutine() > before {
		if time.Now().After(deadline) {
			buf := make([]byte, 1<<20)
			n := runtime.Stack(buf, true)
			t.Fatalf("goroutines: %d after, %d before\n%s", runtime.NumGoroutine(), before, buf[:n])
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func TestBootServeAndShutdown(t *testing.T) {
	before := runtime.NumGoroutine()
	f := newFixture(t)
	opts := f.options(t)

	a, err := New(context.Background(), f.env, opts)
	if err != nil {
		t.Fatal(err)
	}
	// Before Run: not ready, application routes refused.
	rec := httpRecorder(a.Handler(), "/healthz")
	if rec != http.StatusServiceUnavailable {
		t.Fatalf("healthz before Run: %d", rec)
	}
	if code := httpRecorder(a.Handler(), "/acme/directory"); code != http.StatusServiceUnavailable {
		t.Fatalf("acme before Run: %d", code)
	}
	if gens, _ := a.Config().Generations(context.Background()); len(gens) != 1 {
		t.Fatalf("first start generations: %+v", gens)
	}
	if _, chk, err := a.Config().Activate(context.Background(), []byte(testYAML)); err != nil || !chk.OK() {
		t.Fatalf("activate: %v %+v", err, chk)
	}
	ctx, cancel := context.WithCancel(context.Background())
	r := &running{t: t, app: a, base: "http://" + a.Addr().String(), cancel: cancel, done: make(chan error, 1),
		client: &http.Client{Transport: &http.Transport{}, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}
	go func() { r.done <- a.Run(ctx) }()
	waitReady(t, r)

	if code, _, body := r.get("/healthz"); code != 200 || !strings.Contains(body, `"ok"`) {
		t.Fatalf("healthz: %d %s", code, body)
	}
	code, hdr, body := r.get("/acme/directory")
	if code != 200 || !strings.Contains(body, "http://broker.test/acme/new-nonce") && !strings.Contains(body, "newNonce") {
		t.Fatalf("directory: %d %s", code, body)
	}
	if hdr.Get("X-Request-ID") == "" {
		t.Error("no X-Request-ID")
	}
	// The peer is a trusted proxy, so its request ID is kept: RealIP must
	// run before RequestID in the chain.
	if _, hdr, _ := r.get("/acme/directory", "X-Request-ID", "proxy-id-42"); hdr.Get("X-Request-ID") != "proxy-id-42" {
		t.Errorf("trusted proxy request ID replaced by %q", hdr.Get("X-Request-ID"))
	}
	if code, _, body := r.get("/ui/login"); code != 200 || !strings.Contains(body, "Sign in") || strings.Contains(body, "DNS gate is mocked") {
		t.Fatalf("login page: %d", code)
	}
	if code, hdr, _ := r.get("/"); code != http.StatusFound || hdr.Get("Location") != "/ui/" {
		t.Fatalf("root: %d %q", code, hdr.Get("Location"))
	}
	// Outside the managed zones: 404. Inside but not authorized (no DNS
	// record, no grant): 403.
	if code, _, body := r.get("/cert/host.unmanaged.test"); code != http.StatusNotFound {
		t.Fatalf("unmanaged: %d %s", code, body)
	}
	if code, _, body := r.get("/cert/host.example.com"); code != http.StatusForbidden {
		t.Fatalf("managed, unauthorized: %d %s", code, body)
	}
	// The real-IP header is believed from 127.0.0.1 (trusted): the gate sees
	// 10.9.9.9, which the name resolves to, so it allows and the fake CA
	// issues through the fake Route53.
	f.resolver.SetA("dev.example.com", "10.9.9.9")
	go func() {
		// Drive the fake clock while the DNS-01 engine polls.
		for i := 0; i < 400; i++ {
			time.Sleep(5 * time.Millisecond)
			f.clock.Advance(time.Second)
		}
	}()
	code, _, body = r.get("/cert/dev.example.com", "X-Real-IP", "10.9.9.9")
	if code != http.StatusOK {
		t.Fatalf("direct issuance: %d %s", code, body)
	}
	if code, _, body := r.get("/dns/challenges", "X-Real-IP", "10.9.9.9"); code != http.StatusOK {
		t.Fatalf("dns proxy list: %d %s", code, body)
	}
	code, _, body = r.get("/metrics")
	for _, want := range []string{"tlsbroker_build_info", "tlsbroker_direct_cache_total", `tlsbroker_issuance_total{class="direct_miss",mode="direct",provider="primary",result="ok"} 1`, "tlsbroker_dns01_present_duration_seconds_count 1"} {
		if code != 200 || !strings.Contains(body, want) {
			t.Fatalf("metrics: %d, missing %q", code, want)
		}
	}
	a.Housekeep(context.Background())
	r.stop()

	if code := httpRecorder(a.Handler(), "/healthz"); code != http.StatusServiceUnavailable {
		t.Fatalf("healthz after shutdown: %d", code)
	}
	noLeaks(t, before)

	// Second start on the same data directory: the activated generation is
	// kept and recovery runs on the existing state.
	r2 := start(t, f.env, f.options(t))
	if gen := r2.app.Config().Current().Generation; gen != 2 {
		t.Fatalf("generation after restart: %d", gen)
	}
	if code, _, _ := r2.get("/cert/dev.example.com", "X-Real-IP", "10.9.9.9"); code != http.StatusOK {
		t.Fatalf("cached cert after restart: %d", code)
	}
	r2.stop()
	noLeaks(t, before)
}

// A zone without hosted_zone_id gets its ID from ListHostedZones: in the
// background when the configuration is activated, and synchronously at
// startup. Issuance then writes to the discovered zone.
func TestZoneIDDiscoveredByName(t *testing.T) {
	f := newFixture(t)
	yaml := strings.Replace(testYAML, "    hosted_zone_id: Z1EXAMPLE\n", "", 1)
	if yaml == testYAML {
		t.Fatal("fixture YAML has no hosted_zone_id line to drop")
	}
	a, err := New(context.Background(), f.env, f.options(t))
	if err != nil {
		t.Fatal(err)
	}
	if _, chk, err := a.Config().Activate(context.Background(), []byte(yaml)); err != nil || !chk.OK() {
		t.Fatalf("activate without hosted_zone_id: %v %+v", err, chk)
	}
	ctx, cancel := context.WithCancel(context.Background())
	r := &running{t: t, app: a, base: "http://" + a.Addr().String(), cancel: cancel, done: make(chan error, 1),
		client: &http.Client{Transport: &http.Transport{}, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}
	go func() { r.done <- a.Run(ctx) }()
	waitReady(t, r)
	deadline := time.Now().Add(5 * time.Second)
	for {
		st := a.dnsEngine.ZoneStatuses()
		if len(st) == 1 && st[0].HostedZoneID == "Z1EXAMPLE" && st[0].Resolved {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("zone not discovered after activation: %+v", st)
		}
		time.Sleep(10 * time.Millisecond)
	}
	if z, _ := a.Config().Current().ZoneFor("dev.example.com"); z.HostedZoneID != "" {
		t.Fatal("the discovered ID must not be written into the configuration")
	}
	f.resolver.SetA("dev.example.com", "10.9.9.9")
	go func() {
		for i := 0; i < 400; i++ {
			time.Sleep(5 * time.Millisecond)
			f.clock.Advance(time.Second)
		}
	}()
	if code, _, body := r.get("/cert/dev.example.com", "X-Real-IP", "10.9.9.9"); code != http.StatusOK {
		t.Fatalf("direct issuance through the discovered zone: %d %s", code, body)
	}
	if got := f.r53.Changes("Z1EXAMPLE"); got == 0 {
		t.Fatal("no change was written to the discovered hosted zone")
	}
	r.stop()

	// Restart: New discovers the zone before serving.
	calls := f.r53.Calls(dns01.OpListZones)
	r2 := start(t, f.env, f.options(t))
	defer r2.stop()
	if st := r2.app.dnsEngine.ZoneStatuses(); len(st) != 1 || st[0].HostedZoneID != "Z1EXAMPLE" || !st[0].Resolved {
		t.Fatalf("zone not discovered at startup: %+v", st)
	}
	if f.r53.Calls(dns01.OpListZones) == calls {
		t.Fatal("startup did not list the hosted zones")
	}
}

func waitReady(t *testing.T, r *running) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		if resp, err := r.client.Get(r.base + "/healthz"); err == nil {
			resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return
			}
		}
		if time.Now().After(deadline) {
			t.Fatal("broker did not become ready")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func httpRecorder(h http.Handler, path string) int {
	req, _ := http.NewRequest(http.MethodGet, path, nil)
	req.RemoteAddr = "127.0.0.1:1234"
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec.Code
}

func TestMockedDoHShowsBanner(t *testing.T) {
	f := newFixture(t)
	f.env.DoHEndpoints = []string{"http://127.0.0.1:1/dns-query"}
	opts := f.options(t)
	opts.Resolver = nil
	r := start(t, f.env, opts)
	defer r.stop()
	if _, _, body := r.get("/ui/login"); !strings.Contains(body, "DNS gate is mocked") {
		t.Fatal("no mocked-DNS banner")
	}
}

func TestNewFailsCleanly(t *testing.T) {
	before := runtime.NumGoroutine()
	f := newFixture(t)
	// A configuration directory with only an invalid generation refuses to
	// start; New must close what it opened.
	dir := filepath.Join(f.env.DataDir, "config")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "000001.yaml"), []byte("bogus: [\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	opts := f.options(t)
	defer opts.Listener.Close()
	if _, err := New(context.Background(), f.env, opts); err == nil || !strings.Contains(err.Error(), "configuration") {
		t.Fatalf("expected configuration error, got %v", err)
	}
	noLeaks(t, before)
}

func TestCLIHelpers(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t)
	var out bytes.Buffer

	// validate: good, bad, missing secret.
	good := filepath.Join(t.TempDir(), "good.yaml")
	os.WriteFile(good, []byte(testYAML), 0o600)
	if err := ConfigValidate(ctx, f.env, good, &out); err != nil || !strings.Contains(out.String(), "valid") {
		t.Fatalf("validate good: %v %s", err, out.String())
	}
	bad := filepath.Join(t.TempDir(), "bad.yaml")
	os.WriteFile(bad, []byte("server:\n  read_timeout: 90\nnope: 1\n"), 0o600)
	out.Reset()
	if err := ConfigValidate(ctx, f.env, bad, &out); err == nil || !strings.Contains(out.String(), "error:") {
		t.Fatalf("validate bad: %v %s", err, out.String())
	}

	// apply on a fresh data dir creates generation 1 then 2.
	out.Reset()
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	if err := ConfigApply(ctx, f.env, good, &out, log); err != nil || !strings.Contains(out.String(), "000002") {
		t.Fatalf("apply: %v %s", err, out.String())
	}
	withSecret := filepath.Join(t.TempDir(), "s.yaml")
	os.WriteFile(withSecret, []byte(testYAML+"route53:\n  access_key_id_secret: a\n  secret_access_key_secret: b\n"), 0o600)
	out.Reset()
	if err := ConfigValidate(ctx, f.env, withSecret, &out); err == nil || !strings.Contains(out.String(), "secret") {
		t.Fatalf("validate missing secret: %v %s", err, out.String())
	}

	// users: set-role creates, block needs an existing user.
	out.Reset()
	if err := SetBlocked(ctx, f.env, "Carol", false, true, &out); err == nil {
		t.Fatal("block of an unknown user succeeded")
	}
	if err := SetRole(ctx, f.env, "Carol", false, core.RoleAdmin, &out); err != nil {
		t.Fatal(err)
	}
	if err := SetRole(ctx, f.env, "carol", false, core.Role("boss"), &out); err == nil {
		t.Fatal("unknown role accepted")
	}
	if err := SetBlocked(ctx, f.env, "carol", false, true, &out); err != nil {
		t.Fatal(err)
	}

	// backup, then a running broker sees the same user and health.
	dest := filepath.Join(t.TempDir(), "snap.db")
	if err := Backup(ctx, f.env, dest, &out); err != nil {
		t.Fatal(err)
	}
	if err := Backup(ctx, f.env, dest, &out); err == nil {
		t.Fatal("backup overwrote an existing file")
	}

	r := start(t, f.env, f.options(t))
	defer r.stop()
	u, err := r.app.Store().Users().GetByUsername(ctx, "carol", false)
	if err != nil || u.Role != core.RoleAdmin || !u.Blocked {
		t.Fatalf("carol: %+v %v", u, err)
	}
	if gen := r.app.Config().Current().Generation; gen != 2 {
		t.Fatalf("generation: %d", gen)
	}
	env := f.env
	env.Listen = strings.Replace(r.app.Addr().String(), "127.0.0.1", "0.0.0.0", 1)
	if err := HealthCheck(ctx, env); err != nil {
		t.Fatal(err)
	}
	env.Listen = "127.0.0.1:1"
	if err := HealthCheck(ctx, env); err == nil {
		t.Fatal("health check of nothing succeeded")
	}
	evs, err := r.app.auditLog.Query(ctx, core.AuditQuery{Type: core.AuditUserChange})
	if err != nil || len(evs) != 2 {
		t.Fatalf("user_change events: %d %v", len(evs), err)
	}
}

// countingTester counts LDAP tests.
type countingTester struct {
	mu sync.Mutex
	n  int
}

func (c *countingTester) TestLDAP(context.Context, core.LDAPConfig) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.n++
	return nil
}

func (c *countingTester) calls() int { c.mu.Lock(); defer c.mu.Unlock(); return c.n }

// The broker checks LDAP by itself once at startup and once per generation
// that changes the LDAP settings, never for other changes and never when
// LDAP is not configured.
func TestLDAPCheckedAtStartupAndOnChange(t *testing.T) {
	f := newFixture(t)
	opts := f.options(t)
	tester := &countingTester{}
	opts.LDAPTester = tester
	wait := func(want int) {
		t.Helper()
		deadline := time.Now().Add(5 * time.Second)
		for tester.calls() < want && time.Now().Before(deadline) {
			time.Sleep(5 * time.Millisecond)
		}
		time.Sleep(50 * time.Millisecond) // and no more than that
		if got := tester.calls(); got != want {
			t.Fatalf("LDAP tests: %d, want %d", got, want)
		}
	}
	r := start(t, f.env, opts)
	wait(0) // no LDAP configured
	ldap := testYAML + "ldap:\n  url: ldaps://ldap.example.com:636\n  base_dn: dc=example,dc=com\n  user_filter: (uid=%s)\n"
	activate := func(yaml string) {
		t.Helper()
		if _, chk, err := r.app.Config().Activate(context.Background(), []byte(yaml)); err != nil || !chk.OK() {
			t.Fatalf("activate: %v %+v", err, chk)
		}
	}
	activate(ldap)
	wait(2) // the activation's own test, then the background check
	activate(strings.Replace(ldap, "trusted_proxies: [127.0.0.1]", "trusted_proxies: [127.0.0.1, 10.0.0.1]", 1))
	wait(2)
	activate(strings.Replace(ldap, "(uid=%s)", "(cn=%s)", 1))
	wait(4)
	r.stop()

	opts = f.options(t)
	opts.LDAPTester = tester
	r = start(t, f.env, opts)
	defer r.stop()
	wait(5) // startup
}
