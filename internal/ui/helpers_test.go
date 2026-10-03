package ui

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"tls-broker/internal/audit"
	"tls-broker/internal/auth"
	"tls-broker/internal/config"
	"tls-broker/internal/core"
	"tls-broker/internal/core/coretest"
	"tls-broker/internal/store"
)

var bg = context.Background()

const goodYAML = `server:
  external_url: https://broker.example.com
zones:
  - name: example.com
    hosted_zone_id: Z0123456789ABC
providers:
  - name: letsencrypt
    directory_url: https://acme.example/dir
    caa_issuers: [letsencrypt.org]
    account_uri_honoured: true
`

type ldapStub struct {
	mu    sync.Mutex
	err   error
	calls int
}

func (l *ldapStub) TestLDAP(context.Context, core.LDAPConfig) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.calls++
	return l.err
}

func (l *ldapStub) set(err error) { l.mu.Lock(); l.err = err; l.mu.Unlock() }

type caaStub struct {
	mu sync.Mutex
	m  map[string]core.CAAStatus
}

func (c *caaStub) CheckCAA(_ context.Context, name string) (core.CAAStatus, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if st, ok := c.m[name]; ok {
		return st, nil
	}
	return core.CAAStatus{Name: name, Detail: "no CAA records: any CA may issue wildcards"}, nil
}

type rotatorStub struct{ got []string }

func (r *rotatorStub) Rotate(_ context.Context, id string) error {
	r.got = append(r.got, id)
	return nil
}

type env struct {
	t       *testing.T
	clock   *coretest.FakeClock
	store   *store.Store
	cfg     *config.Store
	secrets *config.FileSecrets
	dir     *coretest.FakeDirectory
	audit   *audit.Log
	sched   *coretest.FakeScheduler
	ca      *coretest.FakeCA
	ldap    *ldapStub
	caa     *caaStub
	auth    *auth.Service
	h       *Handler
	srv     *httptest.Server
}

type envOpts struct {
	rotator KeyRotator
	banners []string
	noYAML  bool
}

func newEnv(t *testing.T, o ...envOpts) *env {
	t.Helper()
	var opt envOpts
	if len(o) > 0 {
		opt = o[0]
	}
	e := &env{t: t, clock: coretest.NewFakeClock(coretest.At(2026, 10, 2, 12)), dir: coretest.NewFakeDirectory(), ldap: &ldapStub{}, caa: &caaStub{m: map[string]core.CAAStatus{}}}
	data := t.TempDir()
	var err error
	if e.store, err = store.Open(filepath.Join(data, "state.db")); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { e.store.Close() })
	if e.secrets, err = config.NewFileSecrets(data); err != nil {
		t.Fatal(err)
	}
	env := config.DefaultEnv()
	env.DataDir = data
	env.Bootstrap = core.BootstrapConfig{Admins: []string{"alice"}, LocalAdminUser: "root", LocalAdminPassword: "rootpw"}
	if e.cfg, err = config.Open(config.Options{Env: env, Secrets: e.secrets, LDAP: e.ldap, Logger: slog.New(slog.NewTextHandler(io.Discard, nil))}); err != nil {
		t.Fatal(err)
	}
	if e.audit, err = audit.Open(audit.Options{Dir: filepath.Join(data, "audit"), Clock: e.clock, SyncInterval: -1}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { e.audit.Close() })
	e.auth = auth.New(auth.Deps{Config: e.cfg, Users: e.store.Users(), Sessions: e.store.Sessions(), Directory: e.dir, Clock: e.clock, Audit: e.audit})
	e.sched = coretest.NewFakeScheduler()
	e.ca = coretest.NewFakeCA("letsencrypt", e.clock)
	for _, u := range []string{"alice", "bob", "carol", "dave"} {
		e.dir.SetUser(u, u+"-pw")
	}
	h, err := New(Deps{
		Auth: e.auth, Config: e.cfg, Admin: e.cfg, Secrets: e.secrets, LDAP: e.ldap, CAA: e.caa,
		Providers: coretest.NewFakeProviders(e.ca), Scheduler: e.sched, Audit: e.audit, Auditor: e.audit,
		Users: e.store.Users(), Grants: e.store.Grants(), Certs: e.store.Certificates(), Orders: e.store.Orders(),
		Direct: e.store.Direct(), Lineages: e.store.Lineages(), Clock: e.clock, Rotator: opt.rotator, Banners: opt.banners,
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	if err != nil {
		t.Fatal(err)
	}
	e.h = h
	e.srv = httptest.NewServer(h)
	t.Cleanup(e.srv.Close)
	if !opt.noYAML {
		if _, chk, err := e.cfg.Activate(bg, []byte(goodYAML)); err != nil || !chk.OK() {
			t.Fatalf("activate fixture config: %v %+v", err, chk)
		}
	}
	return e
}

// client is a browser stand-in: it keeps cookies by hand (the session cookie
// is Secure, which a cookie jar would refuse to send over http) and never
// follows redirects.
type client struct {
	e       *env
	cookies map[string]string
}

func (e *env) client() *client {
	return &client{e: e, cookies: map[string]string{}}
}

// login logs in and returns the client; the user is created on first login.
func (e *env) login(user string) *client {
	e.t.Helper()
	c := e.client()
	pw := user + "-pw"
	if user == "root" {
		pw = "rootpw"
	}
	r := c.post("/ui/login", url.Values{"username": {user}, "password": {pw}})
	if r.code != http.StatusSeeOther {
		e.t.Fatalf("login %s: %d %s", user, r.code, r.body)
	}
	return c
}

// loginAs logs in user after setting its role/blocked state directly.
func (e *env) loginAs(user string, role core.Role) *client {
	e.t.Helper()
	c := e.login(user)
	u, err := e.store.Users().GetByUsername(bg, user, false)
	if err != nil {
		e.t.Fatal(err)
	}
	if err := e.store.Users().SetRole(bg, u.ID, role); err != nil {
		e.t.Fatal(err)
	}
	return c
}

func (e *env) userID(name string) int64 {
	e.t.Helper()
	u, err := e.store.Users().GetByUsername(bg, name, false)
	if err != nil {
		e.t.Fatal(err)
	}
	return u.ID
}

type resp struct {
	code int
	body string
	hdr  http.Header
}

func (c *client) send(req *http.Request) resp {
	c.e.t.Helper()
	for k, v := range c.cookies {
		req.AddCookie(&http.Cookie{Name: k, Value: v})
	}
	res, err := (&http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}).Do(req)
	if err != nil {
		c.e.t.Fatal(err)
	}
	defer res.Body.Close()
	b, _ := io.ReadAll(res.Body)
	for _, ck := range res.Cookies() {
		if ck.MaxAge < 0 || ck.Value == "" {
			delete(c.cookies, ck.Name)
		} else {
			c.cookies[ck.Name] = ck.Value
		}
	}
	return resp{res.StatusCode, string(b), res.Header}
}

func (c *client) get(path string) resp {
	req, _ := http.NewRequest("GET", c.e.srv.URL+path, nil)
	return c.send(req)
}

func (c *client) post(path string, form url.Values) resp {
	req, _ := http.NewRequest("POST", c.e.srv.URL+path, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	return c.send(req)
}

var csrfRe = regexp.MustCompile(`name="csrf_token" value="([^"]+)"`)

func (c *client) csrf() string {
	c.e.t.Helper()
	r := c.get("/ui/grants")
	m := csrfRe.FindStringSubmatch(r.body)
	if m == nil {
		c.e.t.Fatalf("no csrf token in page: %d", r.code)
	}
	return m[1]
}

// act posts form with the session's CSRF token.
func (c *client) act(path string, form url.Values) resp {
	c.e.t.Helper()
	if form == nil {
		form = url.Values{}
	}
	form.Set("csrf_token", c.csrf())
	return c.post(path, form)
}

// follow GETs the redirect target of r (so the flash message shows).
func (c *client) follow(r resp) resp {
	c.e.t.Helper()
	loc := r.hdr.Get("Location")
	if r.code != http.StatusSeeOther || loc == "" {
		c.e.t.Fatalf("not a redirect: %d", r.code)
	}
	return c.get(loc)
}

func see(t *testing.T, r resp, subs ...string) {
	t.Helper()
	for _, s := range subs {
		if !strings.Contains(r.body, s) {
			t.Errorf("body lacks %q\n%s", s, trim(r.body))
		}
	}
}

func lacks(t *testing.T, r resp, subs ...string) {
	t.Helper()
	for _, s := range subs {
		if strings.Contains(r.body, s) {
			t.Errorf("body contains %q\n%s", s, trim(r.body))
		}
	}
}

func trim(s string) string {
	if len(s) > 3000 {
		return s[:3000] + "..."
	}
	return s
}

func code(t *testing.T, r resp, want int) {
	t.Helper()
	if r.code != want {
		t.Errorf("status %d, want %d\n%s", r.code, want, trim(r.body))
	}
}

var errLDAPDown = errors.New("dial tcp: connection refused")

var _ = time.Second

func mustAddr(s string) netip.Addr { return netip.MustParseAddr(s) }
