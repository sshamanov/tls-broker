package auth

import (
	"context"
	"crypto/tls"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-ldap/ldap/v3"

	"tls-broker/internal/core"
	"tls-broker/internal/core/coretest"
)

// fakeConn is a scripted LDAP connection.
type fakeConn struct {
	mu        sync.Mutex
	binds     []string // "dn:password"
	searches  []*ldap.SearchRequest
	startTLS  int
	closed    int
	entries   []string          // DNs returned by Search
	searchErr error             // returned by Search
	passwords map[string]string // dn -> password accepted by Bind
	bindErr   error             // forced Bind error for every bind
	tlsErr    error
}

func (c *fakeConn) StartTLS(*tls.Config) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.startTLS++
	return c.tlsErr
}
func (c *fakeConn) Bind(dn, pw string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.binds = append(c.binds, dn+":"+pw)
	if c.bindErr != nil {
		return c.bindErr
	}
	if want, ok := c.passwords[dn]; ok && want == pw && pw != "" {
		return nil
	}
	return ldap.NewError(ldap.LDAPResultInvalidCredentials, errors.New("bad password"))
}
func (c *fakeConn) Search(r *ldap.SearchRequest) (*ldap.SearchResult, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.searches = append(c.searches, r)
	if c.searchErr != nil {
		return nil, c.searchErr
	}
	res := &ldap.SearchResult{}
	for _, dn := range c.entries {
		res.Entries = append(res.Entries, &ldap.Entry{DN: dn})
	}
	return res, nil
}
func (c *fakeConn) Close() error { c.mu.Lock(); c.closed++; c.mu.Unlock(); return nil }

type ldapEnv struct {
	l     *LDAP
	conn  *fakeConn
	cfg   *coretest.FakeConfig
	dials int
	dialE error
}

func newLDAPEnv(t *testing.T) *ldapEnv {
	t.Helper()
	e := &ldapEnv{conn: &fakeConn{
		entries:   []string{"uid=alice,ou=people,dc=example,dc=com"},
		passwords: map[string]string{"cn=svc,dc=example,dc=com": "svcpw", "uid=alice,ou=people,dc=example,dc=com": "alicepw"},
	}}
	c := coretest.NewConfig()
	c.LDAP = core.LDAPConfig{
		URL: "ldaps://ldap.example.com:636", BindDN: "cn=svc,dc=example,dc=com", BindPasswordSecret: "ldap-bind",
		BaseDN: "dc=example,dc=com", UserFilter: "(&(objectClass=person)(uid=%s))", Timeout: 5 * time.Second,
	}
	e.cfg = coretest.NewFakeConfig(c)
	sec := coretest.NewFakeSecrets()
	_ = sec.Put(context.Background(), "ldap-bind", []byte("svcpw"))
	e.l = NewLDAP(e.cfg, sec, WithDialer(func(context.Context, string, time.Duration, *tls.Config) (Conn, error) {
		e.dials++
		if e.dialE != nil {
			return nil, e.dialE
		}
		return e.conn, nil
	}))
	return e
}

func TestLDAPSuccess(t *testing.T) {
	e := newLDAPEnv(t)
	if err := e.l.Authenticate(context.Background(), "alice", "alicepw"); err != nil {
		t.Fatal(err)
	}
	want := []string{"cn=svc,dc=example,dc=com:svcpw", "uid=alice,ou=people,dc=example,dc=com:alicepw"}
	if strings.Join(e.conn.binds, "|") != strings.Join(want, "|") {
		t.Fatalf("binds %v", e.conn.binds)
	}
	if e.conn.closed == 0 {
		t.Fatal("connection not closed")
	}
	r := e.conn.searches[0]
	if r.BaseDN != "dc=example,dc=com" || r.Filter != "(&(objectClass=person)(uid=alice))" {
		t.Fatalf("search %q %q", r.BaseDN, r.Filter)
	}
}

func TestLDAPFilterEscaping(t *testing.T) {
	e := newLDAPEnv(t)
	e.conn.entries = nil
	err := e.l.Authenticate(context.Background(), "*)(uid=*))(|(uid=*", "x")
	if !errors.Is(err, core.ErrInvalidCredentials) {
		t.Fatalf("err %v", err)
	}
	got := e.conn.searches[0].Filter
	want := `(&(objectClass=person)(uid=\2a\29\28uid=\2a\29\29\28|\28uid=\2a))`
	if got != want {
		t.Fatalf("filter %q, want %q", got, want)
	}
	if _, err := ldap.CompileFilter(got); err != nil {
		t.Fatal(err)
	}
}

func TestLDAPEmptyPasswordNeverBinds(t *testing.T) {
	e := newLDAPEnv(t)
	for _, u := range []string{"alice", ""} {
		if err := e.l.Authenticate(context.Background(), u, ""); !errors.Is(err, core.ErrInvalidCredentials) {
			t.Fatalf("err %v", err)
		}
	}
	if e.dials != 0 || len(e.conn.binds) != 0 {
		t.Fatalf("dials %d binds %v", e.dials, e.conn.binds)
	}
}

func TestLDAPMatchCount(t *testing.T) {
	ctx := context.Background()
	e := newLDAPEnv(t)
	e.conn.entries = nil
	if err := e.l.Authenticate(ctx, "alice", "alicepw"); !errors.Is(err, core.ErrInvalidCredentials) {
		t.Fatalf("zero: %v", err)
	}
	e.conn.entries = []string{"uid=alice,ou=a,dc=example,dc=com", "uid=alice,ou=b,dc=example,dc=com"}
	e.conn.binds = nil
	if err := e.l.Authenticate(ctx, "alice", "alicepw"); !errors.Is(err, core.ErrInvalidCredentials) {
		t.Fatalf("multiple: %v", err)
	}
	if len(e.conn.binds) != 1 { // service bind only, no user bind
		t.Fatalf("binds %v", e.conn.binds)
	}
	e.conn.entries = nil
	e.conn.searchErr = ldap.NewError(ldap.LDAPResultSizeLimitExceeded, errors.New("size"))
	if err := e.l.Authenticate(ctx, "alice", "alicepw"); !errors.Is(err, core.ErrInvalidCredentials) {
		t.Fatalf("size limit: %v", err)
	}
}

func TestLDAPWrongPassword(t *testing.T) {
	e := newLDAPEnv(t)
	if err := e.l.Authenticate(context.Background(), "alice", "nope"); !errors.Is(err, core.ErrInvalidCredentials) {
		t.Fatalf("err %v", err)
	}
}

func TestLDAPUnavailable(t *testing.T) {
	ctx := context.Background()
	check := func(name string, e *ldapEnv) {
		t.Helper()
		err := e.l.Authenticate(ctx, "alice", "alicepw")
		if !errors.Is(err, core.ErrDirectoryUnavailable) || errors.Is(err, core.ErrInvalidCredentials) {
			t.Fatalf("%s: %v", name, err)
		}
	}
	e := newLDAPEnv(t)
	e.dialE = errors.New("connection refused")
	check("dial", e)

	e = newLDAPEnv(t)
	e.conn.bindErr = ldap.NewError(ldap.LDAPResultInvalidCredentials, errors.New("x"))
	check("service bind rejected", e)

	e = newLDAPEnv(t)
	e.conn.searchErr = ldap.NewError(ldap.LDAPResultNoSuchObject, errors.New("x"))
	check("bad base", e)

	e = newLDAPEnv(t)
	e.cfg.Update(func(c *core.Config) { c.LDAP.URL = "" })
	check("not configured", e)

	e = newLDAPEnv(t)
	e.cfg.Update(func(c *core.Config) { c.LDAP.UserFilter = "(uid=%s" })
	check("bad filter", e)
	e.cfg.Update(func(c *core.Config) { c.LDAP.UserFilter = "(uid=bob)" })
	check("filter without %s", e)

	e = newLDAPEnv(t)
	e.cfg.Update(func(c *core.Config) { c.LDAP.BindPasswordSecret = "missing" })
	check("missing secret", e)
}

func TestLDAPContextCancel(t *testing.T) {
	e := newLDAPEnv(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := e.l.Authenticate(ctx, "alice", "alicepw"); !errors.Is(err, context.Canceled) {
		t.Fatalf("err %v", err)
	}
}

func TestLDAPStartTLS(t *testing.T) {
	e := newLDAPEnv(t)
	e.cfg.Update(func(c *core.Config) { c.LDAP.URL = "ldap://ldap.example.com"; c.LDAP.StartTLS = true })
	if err := e.l.Authenticate(context.Background(), "alice", "alicepw"); err != nil {
		t.Fatal(err)
	}
	if e.conn.startTLS != 1 {
		t.Fatalf("startTLS %d", e.conn.startTLS)
	}
	// StartTLS must happen before any bind.
	e.conn.tlsErr = errors.New("no tls")
	e.conn.binds = nil
	err := e.l.Authenticate(context.Background(), "alice", "alicepw")
	if !errors.Is(err, core.ErrDirectoryUnavailable) || len(e.conn.binds) != 0 {
		t.Fatalf("err %v binds %v", err, e.conn.binds)
	}
	// ldaps never calls StartTLS.
	e = newLDAPEnv(t)
	e.cfg.Update(func(c *core.Config) { c.LDAP.StartTLS = true })
	_ = e.l.Authenticate(context.Background(), "alice", "alicepw")
	if e.conn.startTLS != 0 {
		t.Fatal("StartTLS on ldaps")
	}
}

func TestLDAPPassesTLSConfig(t *testing.T) {
	e := newLDAPEnv(t)
	var got *tls.Config
	var gotTimeout time.Duration
	e.l.dial = func(_ context.Context, _ string, to time.Duration, tc *tls.Config) (Conn, error) {
		got, gotTimeout = tc, to
		return e.conn, nil
	}
	e.cfg.Update(func(c *core.Config) { c.LDAP.InsecureSkipVerify = true })
	_ = e.l.Authenticate(context.Background(), "alice", "alicepw")
	if got.ServerName != "ldap.example.com" || !got.InsecureSkipVerify || gotTimeout != 5*time.Second {
		t.Fatalf("%+v %v", got, gotTimeout)
	}
}

func TestTestLDAP(t *testing.T) {
	ctx := context.Background()
	e := newLDAPEnv(t)
	e.conn.entries = nil // probe name matches nothing: that is fine
	cfg := e.cfg.Current().LDAP
	if err := e.l.TestLDAP(ctx, cfg); err != nil {
		t.Fatal(err)
	}
	if len(e.conn.binds) != 1 || len(e.conn.searches) != 1 || !strings.Contains(e.conn.searches[0].Filter, probeUsername) {
		t.Fatalf("binds %v searches %v", e.conn.binds, e.conn.searches)
	}
	// Candidate settings are tested, not the active ones.
	bad := cfg
	bad.BindPasswordSecret = "missing"
	if err := e.l.TestLDAP(ctx, bad); !errors.Is(err, core.ErrDirectoryUnavailable) {
		t.Fatalf("err %v", err)
	}
	bad = cfg
	bad.UserFilter = "(uid="
	if err := e.l.TestLDAP(ctx, bad); err == nil {
		t.Fatal("bad filter accepted")
	}
	e.conn.searchErr = ldap.NewError(ldap.LDAPResultNoSuchObject, errors.New("x"))
	if err := e.l.TestLDAP(ctx, cfg); err == nil {
		t.Fatal("bad base accepted")
	}
}
