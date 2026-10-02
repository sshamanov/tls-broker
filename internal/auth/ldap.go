// Package auth is human authentication for the UI: LDAP verification, the
// environment-driven bootstrap administrators, sessions, login throttling and
// the HTTP helpers (cookie, middleware, CSRF). See docs/authentication.md.
package auth

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"net/url"
	"strings"
	"time"

	"github.com/go-ldap/ldap/v3"

	"tls-broker/internal/core"
)

// Conn is the part of an LDAP connection this package uses. *ldap.Conn
// implements it; tests use a fake.
type Conn interface {
	StartTLS(cfg *tls.Config) error
	Bind(dn, password string) error
	Search(req *ldap.SearchRequest) (*ldap.SearchResult, error)
	Close() error
}

// Dialer opens an unauthenticated connection. For an ldaps:// URL the
// connection is already TLS (using tlsCfg); StartTLS is applied by the caller.
type Dialer func(ctx context.Context, url string, timeout time.Duration, tlsCfg *tls.Config) (Conn, error)

// probeUsername is the name TestLDAP puts into the user filter.
const probeUsername = "tls-broker-ldap-probe"

// LDAP implements core.Directory and core.LDAPTester on go-ldap.
type LDAP struct {
	cfg     core.ConfigSource
	secrets core.SecretStore
	dial    Dialer
	roots   *x509.CertPool
}

var (
	_ core.Directory  = (*LDAP)(nil)
	_ core.LDAPTester = (*LDAP)(nil)
)

// LDAPOption customises NewLDAP.
type LDAPOption func(*LDAP)

// WithRootCAs makes LDAP trust the given pool instead of the system roots,
// for a directory whose certificate is signed by a private CA.
func WithRootCAs(pool *x509.CertPool) LDAPOption { return func(l *LDAP) { l.roots = pool } }

// WithDialer replaces the network dialer (tests).
func WithDialer(d Dialer) LDAPOption { return func(l *LDAP) { l.dial = d } }

// NewLDAP returns the directory. Settings are read from cfg.Current().LDAP on
// every call, so a configuration reload applies at once.
func NewLDAP(cfg core.ConfigSource, secrets core.SecretStore, opts ...LDAPOption) *LDAP {
	l := &LDAP{cfg: cfg, secrets: secrets, dial: dialLDAP}
	for _, o := range opts {
		o(l)
	}
	return l
}

func unavailable(format string, args ...any) error {
	return fmt.Errorf("%w: %s", core.ErrDirectoryUnavailable, fmt.Sprintf(format, args...))
}

// Authenticate implements core.Directory.
func (l *LDAP) Authenticate(ctx context.Context, username, password string) error {
	// Never reach a bind with an empty password: LDAP treats a bind with a
	// DN and an empty password as an unauthenticated bind that succeeds.
	if username == "" || password == "" {
		return core.ErrInvalidCredentials
	}
	cfg := l.cfg.Current().LDAP
	conn, closeFn, err := l.open(ctx, cfg)
	if err != nil {
		return err
	}
	defer closeFn()

	dn, err := l.findUser(ctx, conn, cfg, username)
	if err != nil {
		return err
	}
	if err := conn.Bind(dn, password); err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if ldap.IsErrorWithCode(err, ldap.LDAPResultInvalidCredentials) {
			return core.ErrInvalidCredentials
		}
		return unavailable("user bind: %v", err)
	}
	return nil
}

// TestLDAP implements core.LDAPTester.
func (l *LDAP) TestLDAP(ctx context.Context, cfg core.LDAPConfig) error {
	conn, closeFn, err := l.open(ctx, cfg)
	if err != nil {
		return err
	}
	defer closeFn()
	// Zero matches for the probe is the expected, healthy answer; only a
	// failure to run the search matters.
	if _, err := l.search(ctx, conn, cfg, probeUsername); err != nil {
		return err
	}
	return nil
}

// open connects, upgrades with StartTLS when configured and binds with the
// service account. The returned func closes the connection.
func (l *LDAP) open(ctx context.Context, cfg core.LDAPConfig) (Conn, func(), error) {
	if cfg.URL == "" {
		return nil, nil, unavailable("LDAP is not configured")
	}
	if cfg.BaseDN == "" {
		return nil, nil, unavailable("LDAP base DN is not set")
	}
	if !strings.Contains(cfg.UserFilter, "%s") {
		return nil, nil, unavailable("LDAP user filter must contain %%s")
	}
	if _, err := ldap.CompileFilter(buildFilter(cfg.UserFilter, probeUsername)); err != nil {
		return nil, nil, unavailable("LDAP user filter is invalid: %v", err)
	}
	u, err := url.Parse(cfg.URL)
	if err != nil || u.Hostname() == "" || (u.Scheme != "ldap" && u.Scheme != "ldaps") {
		return nil, nil, unavailable("LDAP URL must be ldap://host or ldaps://host")
	}
	var bindPW []byte
	if cfg.BindDN != "" {
		bindPW, err = l.secrets.Get(ctx, cfg.BindPasswordSecret)
		if err != nil {
			return nil, nil, unavailable("bind password secret %q: %v", cfg.BindPasswordSecret, err)
		}
		if len(bindPW) == 0 {
			return nil, nil, unavailable("bind password secret %q is empty", cfg.BindPasswordSecret)
		}
	}
	timeout := cfg.Timeout
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	tlsCfg := &tls.Config{
		ServerName:         u.Hostname(),
		RootCAs:            l.roots,
		InsecureSkipVerify: cfg.InsecureSkipVerify, //nolint:gosec // operator opt-in
		MinVersion:         tls.VersionTLS12,
	}
	if err := ctx.Err(); err != nil {
		return nil, nil, err
	}
	conn, err := l.dial(ctx, cfg.URL, timeout, tlsCfg)
	if err != nil {
		if ctx.Err() != nil {
			return nil, nil, ctx.Err()
		}
		return nil, nil, unavailable("connect: %v", err)
	}
	// Cancelling ctx closes the connection, which unblocks any operation
	// in flight.
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	closeFn := func() { stop(); _ = conn.Close() }
	fail := func(err error) (Conn, func(), error) {
		closeFn()
		if ctx.Err() != nil {
			return nil, nil, ctx.Err()
		}
		return nil, nil, err
	}
	if u.Scheme == "ldap" && cfg.StartTLS {
		if err := conn.StartTLS(tlsCfg); err != nil {
			return fail(unavailable("StartTLS: %v", err))
		}
	}
	if cfg.BindDN != "" {
		if err := conn.Bind(cfg.BindDN, string(bindPW)); err != nil {
			return fail(unavailable("service account bind: %v", err))
		}
	}
	return conn, closeFn, nil
}

func buildFilter(tmpl, username string) string {
	return strings.ReplaceAll(tmpl, "%s", ldap.EscapeFilter(username))
}

// search runs the user filter and returns the DNs found.
func (l *LDAP) search(ctx context.Context, conn Conn, cfg core.LDAPConfig, username string) ([]string, error) {
	req := ldap.NewSearchRequest(cfg.BaseDN, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases,
		2, int(max(cfg.Timeout, 0)/time.Second), false,
		buildFilter(cfg.UserFilter, username), []string{"1.1"}, nil)
	res, err := conn.Search(req)
	if err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		if ldap.IsErrorWithCode(err, ldap.LDAPResultSizeLimitExceeded) {
			// More than one match; the search asked for at most two.
			return []string{"", ""}, nil
		}
		return nil, unavailable("user search: %v", err)
	}
	dns := make([]string, 0, len(res.Entries))
	for _, e := range res.Entries {
		dns = append(dns, e.DN)
	}
	return dns, nil
}

// findUser returns the DN of the single entry matching the username.
func (l *LDAP) findUser(ctx context.Context, conn Conn, cfg core.LDAPConfig, username string) (string, error) {
	dns, err := l.search(ctx, conn, cfg, username)
	if err != nil {
		return "", err
	}
	if len(dns) != 1 || dns[0] == "" {
		return "", core.ErrInvalidCredentials
	}
	return dns[0], nil
}

// dialLDAP is the production Dialer.
func dialLDAP(_ context.Context, rawURL string, timeout time.Duration, tlsCfg *tls.Config) (Conn, error) {
	c, err := ldap.DialURL(rawURL,
		ldap.DialWithDialer(&net.Dialer{Timeout: timeout}),
		ldap.DialWithTLSConfig(tlsCfg))
	if err != nil {
		return nil, err
	}
	c.SetTimeout(timeout)
	return c, nil
}
