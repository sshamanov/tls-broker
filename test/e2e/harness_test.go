// Package e2e runs the whole broker in-process (internal/app) against fakes
// for every external dependency and drives it through its real HTTP API:
// lego's low-level ACME client for the clean ACME proxy, plain net/http for
// the direct API and the DNS proxy, and a cookie-jar client for the UI.
// Every scenario of architecture §25 is a subtest of TestScenarios; the
// invariants are checked at the end of each (checkInvariants).
//
// Without build tags everything is deterministic and offline: the fake CA,
// fake Route53, fake resolver, fake LDAP directory and fake clock. With the
// `pebble` tag, pebble_test.go wires the real upstream adapter against
// Pebble instead (make e2e-pebble).
package e2e

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"path"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-acme/lego/v5/acme"
	"github.com/go-acme/lego/v5/acme/api"

	"tls-broker/internal/app"
	"tls-broker/internal/audit"
	"tls-broker/internal/config"
	"tls-broker/internal/core"
	"tls-broker/internal/core/coretest"
	"tls-broker/internal/dns01"
)

// Hosted zones of the two managed zones.
const (
	zoneCOM = "Z1EXAMPLECOM"
	zoneORG = "Z2EXAMPLEORG"
)

// Day is a calendar day on the fake clock.
const day = 24 * time.Hour

// directKey is the one RSA key every direct-mode issuance uses (RSA
// generation is slow under -race).
var directKey = sync.OnceValue(coretest.GenRSAKey)

// fakeYAML is the configuration of the fake world: two managed zones, the
// primary `letsencrypt` fake (ARI exempt) and the fallback `google` fake
// (ARI without exemption). %s is the broker's external URL.
const fakeYAML = `server:
  external_url: %s
  trusted_proxies: [127.0.0.1]
  real_ip_header: X-Real-IP
  shutdown_grace: 2s
zones:
  - name: example.com
    hosted_zone_id: ` + zoneCOM + `
  - name: example.org
    hosted_zone_id: ` + zoneORG + `
route53:
  poll_interval: 1s
providers:
  - name: letsencrypt
    directory_url: https://letsencrypt.test/directory
    caa_issuers: [letsencrypt.test]
    account_uri_honoured: true
    ari: true
    ari_exempt: true
  - name: google
    directory_url: https://google.test/directory
    caa_issuers: [google.test]
    account_uri_honoured: true
    ari: true
    ari_exempt: false
`

type okLDAP struct{}

func (okLDAP) TestLDAP(context.Context, core.LDAPConfig) error { return nil }

// broker is one broker instance with its fakes, reachable through an HTTPS
// test server that survives restarts of the app behind it (so URLs, and the
// ACME account and order URLs built from them, stay the same).
type broker struct {
	t     *testing.T
	clock core.Clock
	fc    *coretest.FakeClock // nil with the system clock

	le, goog  *coretest.FakeCA // nil with real providers
	providers core.Providers
	roots     *x509.CertPool // UpstreamRootCAs for real providers
	r53       *dns01.FakeRoute53
	route53   dns01.Route53API // what the app gets (r53 or a wrapper)
	dns       *coretest.FakeResolver
	dir       *coretest.FakeDirectory
	env       config.Env
	yaml      string
	srv       *httptest.Server

	cur     atomic.Pointer[app.App]
	cancel  context.CancelFunc
	runDone chan error
}

// newFakeBroker boots a broker on the fake world and activates fakeYAML.
func newFakeBroker(t *testing.T) *broker {
	t.Helper()
	fc := coretest.NewFakeClock(coretest.At(2026, 10, 3, 12))
	b := &broker{t: t, clock: fc, fc: fc,
		le: coretest.NewFakeCA("letsencrypt", fc), goog: coretest.NewFakeCA("google", fc),
		r53: dns01.NewFakeRoute53(fc), dns: coretest.NewFakeResolver(), dir: coretest.NewFakeDirectory()}
	b.goog.SetCaps(core.ProviderCaps{ARI: true, ARIExempt: false, CAAIssuers: []string{"google.test"}, AccountURIHonoured: true})
	b.providers = coretest.NewFakeProviders(b.le, b.goog)
	b.r53.AddZone(zoneCOM, "example.com")
	b.r53.AddZone(zoneORG, "example.org")
	b.route53 = b.r53
	// The CAs validate against Route53's public view, as real CAs would.
	b.le.SetTXTLookup(b.r53.LookupTXT)
	b.goog.SetTXTLookup(b.r53.LookupTXT)
	b.boot(func(external string) string { return fmt.Sprintf(fakeYAML, external) })
	return b
}

// boot creates the HTTPS front, starts the app and activates the YAML that
// yaml builds for the front's external URL.
func (b *broker) boot(yaml func(externalURL string) string) {
	t := b.t
	t.Helper()
	b.dir.SetUser("bob", "bob-pw")
	b.dir.SetUser("carol", "carol-pw")
	b.dir.SetUser("alice", "alice-pw")
	b.env = config.DefaultEnv()
	b.env.DataDir = t.TempDir()
	b.env.Listen = "127.0.0.1:0"
	b.env.Bootstrap = core.BootstrapConfig{Admins: []string{"alice"}}
	b.srv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		a := b.cur.Load()
		if a == nil {
			http.Error(w, "broker down", http.StatusServiceUnavailable)
			return
		}
		a.Handler().ServeHTTP(w, r)
	}))
	t.Cleanup(func() {
		b.stop()
		b.srv.Close()
	})
	b.yaml = yaml(b.srv.URL)
	a := b.newApp()
	if _, chk, err := a.Config().Activate(context.Background(), []byte(b.yaml)); err != nil || !chk.OK() {
		t.Fatalf("activate configuration: %v %+v", err, chk)
	}
	b.run(a)
}

func (b *broker) newApp() *app.App {
	b.t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		b.t.Fatal(err)
	}
	a, err := app.New(context.Background(), b.env, app.Options{
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil)), Clock: b.clock,
		Providers: b.providers, UpstreamRootCAs: b.roots, Route53: b.route53, Resolver: b.r53.Resolver(b.dns),
		Directory: b.dir, LDAPTester: okLDAP{}, Listener: ln,
		NewDirectKey:         func(int) (*rsa.PrivateKey, error) { return directKey(), nil },
		HousekeepingInterval: -1,
	})
	if err != nil {
		_ = ln.Close()
		b.t.Fatalf("app.New: %v", err)
	}
	return a
}

// run serves a until stop and waits until it is ready.
func (b *broker) run(a *app.App) {
	b.t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- a.Run(ctx) }()
	b.cur.Store(a)
	b.cancel, b.runDone = cancel, done
	deadline := time.Now().Add(10 * time.Second)
	for status(a.Handler(), "/healthz") != http.StatusOK {
		if time.Now().After(deadline) {
			b.t.Fatal("broker did not become ready")
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// stop shuts the running app down (Run returns after Close).
func (b *broker) stop() {
	if b.cancel == nil {
		return
	}
	b.cancel()
	select {
	case err := <-b.runDone:
		if err != nil {
			b.t.Errorf("Run: %v", err)
		}
	case <-time.After(60 * time.Second):
		b.t.Error("Run did not return")
	}
	b.cancel = nil
	b.cur.Store(nil)
}

// restart stops the app and starts a new one on the same data directory.
func (b *broker) restart() {
	b.t.Helper()
	b.stop()
	b.run(b.newApp())
}

func (b *broker) app() *app.App { return b.cur.Load() }

func status(h http.Handler, p string) int {
	req := httptest.NewRequest(http.MethodGet, p, nil)
	req.RemoteAddr = "127.0.0.1:1"
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec.Code
}

// housekeep runs one maintenance round (order expiry and the rest).
func (b *broker) housekeep() { b.app().Housekeep(context.Background()) }

// advance moves the fake clock.
func (b *broker) advance(d time.Duration) { b.fc.Advance(d) }

// pump runs f while advancing the fake clock by step every millisecond of
// real time, for code that waits on the clock (Route53 polling, slow CA
// faults, finalize_wait).
func (b *broker) pump(step time.Duration, f func()) {
	stop := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-stop:
				return
			case <-time.After(time.Millisecond):
				b.fc.Advance(step)
			}
		}
	}()
	defer func() {
		close(stop)
		wg.Wait()
	}()
	f()
}

// eventually polls cond in real time for up to 15 s.
func eventually(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(15 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// ---- users and grants -----------------------------------------------------

func (b *broker) user(name string) *core.User {
	b.t.Helper()
	u, _, err := b.app().Store().Users().Ensure(context.Background(), name, false, b.clock.Now())
	if err != nil {
		b.t.Fatal(err)
	}
	return u
}

// grant creates an enabled IP grant owned by bob and returns it.
func (b *broker) grant(prefix string, wildcard bool) *core.Grant {
	b.t.Helper()
	p, err := netip.ParsePrefix(prefix)
	if err != nil {
		p = netip.PrefixFrom(netip.MustParseAddr(prefix), 32)
	}
	g := &core.Grant{OwnerUserID: b.user("bob").ID, Prefix: p.Masked(), Enabled: true, Wildcard: wildcard, CreatedAt: b.clock.Now()}
	if err := b.app().Store().Grants().Create(context.Background(), g); err != nil {
		b.t.Fatal(err)
	}
	return g
}

// auditEvents returns admin-visible audit events of a type.
func (b *broker) auditEvents(typ string) []core.AuditEvent {
	b.t.Helper()
	evs, err := audit.NewReader(filepath.Join(b.env.DataDir, "audit")).Query(context.Background(),
		core.AuditQuery{Type: typ, Limit: 1000})
	if err != nil {
		b.t.Fatal(err)
	}
	return evs
}

// ---- machines: HTTP clients with a source address ---------------------------

// machine is a LAN host: every request carries its address in X-Real-IP,
// which the broker believes from the trusted local front.
type machine struct {
	b    *broker
	ip   string
	tr   *ipTransport
	http *http.Client
}

type ipTransport struct {
	ip   string
	next http.RoundTripper

	mu         sync.Mutex
	lastStatus int
	lastHeader http.Header
}

func (t *ipTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	r = r.Clone(r.Context())
	r.Header.Set("X-Real-IP", t.ip)
	resp, err := t.next.RoundTrip(r)
	if err == nil {
		t.mu.Lock()
		t.lastStatus, t.lastHeader = resp.StatusCode, resp.Header.Clone()
		t.mu.Unlock()
	}
	return resp, err
}

// last returns the status and headers of the latest response.
func (t *ipTransport) last() (int, http.Header) {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.lastStatus, t.lastHeader
}

// machine returns a host at ip. With dnsNames, those names resolve to ip.
func (b *broker) machine(ip string, dnsNames ...string) *machine {
	for _, n := range dnsNames {
		b.dns.SetA(n, ip)
	}
	base := b.srv.Client().Transport.(*http.Transport).Clone()
	tr := &ipTransport{ip: ip, next: base}
	return &machine{b: b, ip: ip, tr: tr, http: &http.Client{Transport: tr, Timeout: 2 * time.Minute,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}
}

// do sends a request and returns status, headers and body.
func (m *machine) do(method, p string, body io.Reader, hdr ...string) (int, http.Header, []byte) {
	m.b.t.Helper()
	req, err := http.NewRequest(method, m.b.srv.URL+p, body)
	if err != nil {
		m.b.t.Fatal(err)
	}
	for i := 0; i+1 < len(hdr); i += 2 {
		req.Header.Set(hdr[i], hdr[i+1])
	}
	resp, err := m.http.Do(req)
	if err != nil {
		m.b.t.Fatalf("%s %s: %v", method, p, err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, resp.Header, b
}

func (m *machine) get(p string, hdr ...string) (int, http.Header, []byte) {
	return m.do(http.MethodGet, p, nil, hdr...)
}

func (m *machine) postJSON(p, body string) (int, http.Header, []byte) {
	return m.do(http.MethodPost, p, strings.NewReader(body), "Content-Type", "application/json")
}

// ---- ACME clients --------------------------------------------------------

// acmeClient is a downstream ACME client (lego's low-level API) with a
// registered account.
type acmeClient struct {
	m    *machine
	core *api.Core
	acct string
}

func (m *machine) acme() *acmeClient {
	m.b.t.Helper()
	key := coretest.GenKey()
	c, err := api.New(m.http, "tlsbroker-e2e", m.b.srv.URL+"/acme/directory", "", key)
	if err != nil {
		m.b.t.Fatal(err)
	}
	acct, err := c.Accounts.New(context.Background(), acme.Account{TermsOfServiceAgreed: true, Contact: []string{"mailto:ops@example.com"}})
	if err != nil {
		m.b.t.Fatal(err)
	}
	return &acmeClient{m: m, core: c, acct: acct.Location}
}

// newOrder sends newOrder; replaces may be empty.
func (c *acmeClient) newOrder(replaces string, names ...string) (acme.ExtendedOrder, error) {
	return c.core.Orders.New(context.Background(), names, &api.OrderOptions{ReplacesCertID: replaces})
}

func (c *acmeClient) mustOrder(replaces string, names ...string) acme.ExtendedOrder {
	c.m.b.t.Helper()
	o, err := c.newOrder(replaces, names...)
	if err != nil {
		c.m.b.t.Fatalf("newOrder %v: %v", names, err)
	}
	if o.Status != acme.StatusReady {
		c.m.b.t.Fatalf("newOrder %v: status %s", names, o.Status)
	}
	return o
}

func (c *acmeClient) finalize(o acme.ExtendedOrder, csr []byte) (acme.ExtendedOrder, error) {
	return c.core.Orders.UpdateForCSR(context.Background(), o.Finalize, csr)
}

// poll fetches the order.
func (c *acmeClient) poll(location string) acme.ExtendedOrder {
	c.m.b.t.Helper()
	o, err := c.core.Orders.Get(context.Background(), location)
	if err != nil {
		c.m.b.t.Fatalf("poll %s: %v", location, err)
	}
	return o
}

// issued is a certificate a downstream client obtained.
type issued struct {
	created acme.ExtendedOrder // the newOrder response
	order   acme.ExtendedOrder // the finalized order
	orderID string
	csr     []byte
	chain   []byte
	leaf    *x509.Certificate
	certID  string // ARI certificate identifier
}

// download fetches the certificate of a valid order.
func (c *acmeClient) download(o acme.ExtendedOrder, csr []byte) *issued {
	t := c.m.b.t
	t.Helper()
	raw, err := c.core.Certificates.Get(context.Background(), o.Certificate, true)
	if err != nil {
		t.Fatalf("download %s: %v", o.Certificate, err)
	}
	chain, err := coretest.ParseChain(raw.Cert)
	if err != nil {
		t.Fatal(err)
	}
	id, err := api.MakeARICertID(chain[0])
	if err != nil {
		t.Fatal(err)
	}
	return &issued{order: o, orderID: path.Base(o.Location), csr: csr, chain: raw.Cert, leaf: chain[0], certID: id}
}

// issue runs a whole ACME issuance (newOrder with optional replaces,
// authorizations, finalize with a fresh key, download) and fails the test
// on any error.
func (c *acmeClient) issue(replaces string, names ...string) *issued {
	t := c.m.b.t
	t.Helper()
	o := c.mustOrder(replaces, names...)
	c.checkAuthzs(o)
	csr := coretest.MakeCSR(coretest.GenKey(), names...)
	fin, err := c.finalize(o, csr)
	if err != nil {
		t.Fatalf("finalize %v: %v", names, err)
	}
	if fin.Status != acme.StatusValid {
		t.Fatalf("finalize %v: status %s", names, fin.Status)
	}
	fin.Location = o.Location
	is := c.download(fin, csr)
	is.created = o
	return is
}

// tryIssue is issue without test failures, for use from goroutines: it
// polls a processing order until it is valid and returns the order.
func (c *acmeClient) tryIssue(names ...string) (acme.ExtendedOrder, error) {
	ctx := context.Background()
	o, err := c.newOrder("", names...)
	if err != nil {
		return o, err
	}
	fin, err := c.core.Orders.UpdateForCSR(ctx, o.Finalize, coretest.MakeCSR(coretest.GenKey(), names...))
	for err == nil && fin.Status == acme.StatusProcessing {
		time.Sleep(5 * time.Millisecond)
		fin, err = c.core.Orders.Get(ctx, o.Location)
	}
	if err == nil && fin.Status != acme.StatusValid {
		err = fmt.Errorf("order %s is %s: %v", o.Location, fin.Status, fin.Err())
	}
	fin.Location = o.Location
	return fin, err
}

// checkAuthzs asserts the already-valid authorization shape: status valid
// and exactly one valid dns-01 challenge; wildcard names carry the base
// identifier and "wildcard": true.
func (c *acmeClient) checkAuthzs(o acme.ExtendedOrder) {
	t := c.m.b.t
	t.Helper()
	if len(o.Authorizations) != len(o.Identifiers) {
		t.Fatalf("%d authorizations for %d identifiers", len(o.Authorizations), len(o.Identifiers))
	}
	for _, u := range o.Authorizations {
		az, err := c.core.Authorizations.Get(context.Background(), u)
		if err != nil {
			t.Fatal(err)
		}
		if az.Status != acme.StatusValid || len(az.Challenges) != 1 || az.Challenges[0].Type != "dns-01" ||
			az.Challenges[0].Status != acme.StatusValid || az.Challenges[0].Token == "" {
			t.Fatalf("authorization %s is not the already-valid shape: %+v", u, az)
		}
		if strings.HasPrefix(az.Identifier.Value, "*.") {
			t.Fatalf("authorization identifier %q carries the wildcard label", az.Identifier.Value)
		}
	}
}

// problem extracts the ACME problem of an error.
func problem(t *testing.T, err error) *acme.ProblemDetails {
	t.Helper()
	var pd *acme.ProblemDetails
	if !errors.As(err, &pd) {
		t.Fatalf("expected an ACME problem, got %v", err)
	}
	return pd
}

// ---- broker-side lookups ---------------------------------------------------

func (b *broker) order(id string) *core.Order {
	b.t.Helper()
	o, err := b.app().Store().Orders().Get(context.Background(), id)
	if err != nil {
		b.t.Fatalf("order %s: %v", id, err)
	}
	return o
}

func (b *broker) certByARI(id string) *core.Certificate {
	b.t.Helper()
	c, err := b.app().Store().Certificates().GetByARICertID(context.Background(), id)
	if err != nil {
		b.t.Fatalf("certificate %s: %v", id, err)
	}
	return c
}

// caOrder returns the upstream order at a fake CA by URL.
func caOrder(ca *coretest.FakeCA, url string) (coretest.CAOrder, bool) {
	for _, o := range ca.Orders() {
		if o.URL == url {
			return o, true
		}
	}
	return coretest.CAOrder{}, false
}

// ---- UI client ------------------------------------------------------------

// uiClient is a browser: a cookie jar and the CSRF token of the session.
type uiClient struct {
	m    *machine
	http *http.Client
	csrf string
}

func (m *machine) browser() *uiClient {
	jar, _ := cookiejar.New(nil)
	return &uiClient{m: m, http: &http.Client{Transport: m.tr, Jar: jar,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}
}

var csrfRE = regexp.MustCompile(`name="csrf_token" value="([^"]+)"`)

func (u *uiClient) do(method, p string, form url.Values) (int, string) {
	t := u.m.b.t
	t.Helper()
	var body io.Reader
	if form != nil {
		if u.csrf != "" {
			form.Set("csrf_token", u.csrf)
		}
		body = strings.NewReader(form.Encode())
	}
	req, _ := http.NewRequest(method, u.m.b.srv.URL+p, body)
	if form != nil {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	resp, err := u.http.Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, p, err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	if m := csrfRE.FindSubmatch(b); m != nil {
		u.csrf = string(m[1])
	}
	return resp.StatusCode, string(b)
}

// login logs in and loads the dashboard (which carries the CSRF token).
func (u *uiClient) login(user, password string) {
	t := u.m.b.t
	t.Helper()
	code, body := u.do(http.MethodPost, "/ui/login", url.Values{"username": {user}, "password": {password}})
	if code != http.StatusSeeOther {
		t.Fatalf("login %s: %d %s", user, code, body)
	}
	if code, body := u.do(http.MethodGet, "/ui/grants", nil); code != http.StatusOK || u.csrf == "" {
		t.Fatalf("grants page after login: %d csrf=%q %.300s", code, u.csrf, body)
	}
}

// ---- invariants -------------------------------------------------------------

// checkInvariants verifies the architecture §25 invariants over everything
// the broker stored during a scenario:
//
//   - one downstream order maps to at most one upstream order: every upstream
//     order at the CAs is owned by exactly one broker order (an adopted one
//     passes from its donor to its adopter), and no broker order created two;
//   - nothing that created upstream issuance bypassed the scheduler: every
//     order that owns an upstream order it created has budget events, or was
//     ARI-qualified (exempt, no budget);
//   - wildcards never succeed without an explicit wildcard IP grant;
//   - an ARI renewal (a certificate that replaced another) stayed with its
//     predecessor's provider and account.
//
// The direct-mode invariants (one job per identifier, cached certificate
// served through an outage, expired never served) are asserted where they
// are exercised. hiddenUpstream is the number of upstream orders the test
// made the CA create without telling the broker (AfterEffect faults).
func (b *broker) checkInvariants(hiddenUpstream int) {
	t := b.t
	t.Helper()
	ctx := context.Background()
	st := b.app().Store()
	orders, err := st.Orders().List(ctx, core.OrderFilter{Limit: 10000})
	if err != nil {
		t.Fatal(err)
	}
	owners := map[string][]string{}
	for _, o := range orders {
		if o.UpstreamOrderURL == "" {
			continue
		}
		if o.AdoptedByOrderID == "" {
			owners[o.UpstreamOrderURL] = append(owners[o.UpstreamOrderURL], o.ID)
		}
		events, err := st.Budgets().ListByRef(ctx, o.ID)
		if err != nil {
			t.Fatal(err)
		}
		adopted := false
		for _, d := range orders {
			if d.AdoptedByOrderID == o.ID {
				adopted = true
			}
		}
		if len(events) == 0 && !o.ARIQualified && !adopted {
			t.Errorf("invariant: order %s (%s) has an upstream order but no budget events and was not ARI-qualified", o.ID, o.Names.Key())
		}
		for _, e := range events {
			if e.Provider != o.Provider {
				t.Errorf("invariant: order %s at %s has budget events at %s", o.ID, o.Provider, e.Provider)
			}
		}
	}
	for u, ids := range owners {
		if len(ids) != 1 {
			t.Errorf("invariant: upstream order %s owned by %d broker orders %v", u, len(ids), ids)
		}
	}
	certs, err := st.Certificates().List(ctx, core.CertificateFilter{Limit: 10000})
	if err != nil {
		t.Fatal(err)
	}
	live := map[string]bool{}
	for _, o := range orders {
		live[o.ID] = true
	}
	created, attributed := 0, len(owners)
	var cas []*coretest.FakeCA
	if b.le != nil {
		cas = append(cas, b.le, b.goog)
	}
	for _, ca := range cas {
		created += ca.Stats().OrdersCreated
		for _, uo := range ca.Orders() {
			if _, ok := owners[uo.URL]; ok {
				continue
			}
			// The broker prunes finished orders after a week; their
			// certificates stay. An upstream order of a pruned broker
			// order is attributed through its certificate.
			if c, err := st.Certificates().GetByARICertID(ctx, uo.CertID); uo.CertID != "" && err == nil && !live[c.OrderID] {
				attributed++
				continue
			}
			if hiddenUpstream == 0 {
				t.Errorf("invariant: upstream order %s at %s belongs to no broker order", uo.URL, ca.Name())
			}
		}
	}
	if cas != nil && created != attributed+hiddenUpstream {
		t.Errorf("invariant: %d upstream orders created for %d broker-owned upstream orders (+%d hidden)", created, attributed, hiddenUpstream)
	}

	byID := map[string]core.Certificate{}
	for _, c := range certs {
		byID[c.ID] = c
	}
	for _, c := range certs {
		if c.Names.HasWildcard() {
			o, err := st.Orders().Get(ctx, c.OrderID)
			if err != nil {
				t.Fatalf("order of certificate %s: %v", c.ID, err)
			}
			g, err := st.Grants().Get(ctx, o.GrantID)
			if o.GrantID == 0 || err != nil || !g.Wildcard {
				t.Errorf("invariant: wildcard certificate %s (%s) issued without a wildcard grant (grant %d)", c.ID, c.Names.Key(), o.GrantID)
			}
		}
		if c.ReplacesID != "" {
			p, ok := byID[c.ReplacesID]
			if !ok {
				t.Errorf("invariant: certificate %s replaces unknown %s", c.ID, c.ReplacesID)
			} else if p.Provider != c.Provider || p.AccountURL != c.AccountURL {
				t.Errorf("invariant: ARI renewal %s moved from %s/%s to %s/%s", c.ID, p.Provider, p.AccountURL, c.Provider, c.AccountURL)
			}
		}
	}
}

// pathBase is the last segment of a URL (an order or certificate ID).
func pathBase(u string) string { return path.Base(u) }
