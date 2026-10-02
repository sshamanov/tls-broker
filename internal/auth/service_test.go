package auth

import (
	"context"
	"errors"
	"net/netip"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"

	"tls-broker/internal/core"
	"tls-broker/internal/core/coretest"
)

var (
	ctx = context.Background()
	ip1 = netip.MustParseAddr("192.0.2.10")
	ip2 = netip.MustParseAddr("192.0.2.11")
)

type env struct {
	s     *Service
	users *memUsers
	sess  *memSessions
	dir   *coretest.FakeDirectory
	clock *coretest.FakeClock
	cfg   *coretest.FakeConfig
	audit *coretest.FakeAuditor
}

func newEnv(t *testing.T) *env {
	t.Helper()
	e := &env{users: newMemUsers(), sess: newMemSessions(), dir: coretest.NewFakeDirectory(), clock: coretest.NewFakeClock()}
	e.cfg = coretest.NewFakeConfig(coretest.NewConfig())
	e.audit = coretest.NewFakeAuditor(e.clock)
	e.s = New(Deps{Config: e.cfg, Users: e.users, Sessions: e.sess, Directory: e.dir, Clock: e.clock, Audit: e.audit})
	e.dir.SetUser("alice", "alicepw")
	return e
}

func TestLDAPLoginCreatesNormalUser(t *testing.T) {
	e := newEnv(t)
	l, err := e.s.Login(ctx, "  Alice ", "alicepw", ip1)
	if err != nil {
		t.Fatal(err)
	}
	if l.User.Username != "alice" || l.User.Role != core.RoleNormal || l.User.Local || l.User.Blocked {
		t.Fatalf("user %+v", l.User)
	}
	if !l.User.LastLoginAt.Equal(e.clock.Now()) {
		t.Fatal("last login not set")
	}
	if l.Token == "" || l.Session.CSRFToken == "" || l.Session.CSRFToken == l.Token {
		t.Fatalf("tokens %+v", l)
	}
	if !l.Session.ExpiresAt.Equal(e.clock.Now().Add(e.cfg.Current().Sessions.TTL)) {
		t.Fatalf("expiry %v", l.Session.ExpiresAt)
	}
	// Second login reuses the user.
	l2, err := e.s.Login(ctx, "alice", "alicepw", ip1)
	if err != nil || l2.User.ID != l.User.ID || l2.Token == l.Token {
		t.Fatalf("%v %+v", err, l2)
	}
}

func TestLoginFailures(t *testing.T) {
	e := newEnv(t)
	for _, c := range [][2]string{{"alice", "wrong"}, {"alice", ""}, {"", "x"}, {"nobody", "x"}} {
		if _, err := e.s.Login(ctx, c[0], c[1], ip1); !errors.Is(err, core.ErrInvalidCredentials) {
			t.Fatalf("%v: %v", c, err)
		}
	}
	if e.sess.count() != 0 {
		t.Fatal("session created")
	}
	if n, _ := e.users.List(ctx); len(n) != 0 {
		t.Fatal("user created on failed login")
	}
}

func TestSessionTokenHashStored(t *testing.T) {
	e := newEnv(t)
	l, _ := e.s.Login(ctx, "alice", "alicepw", ip1)
	if l.Session.TokenHash != core.HashToken(l.Token) || l.Session.TokenHash == l.Token {
		t.Fatal("hash not stored")
	}
	for h, x := range e.sess.m {
		if h == l.Token || x.TokenHash == l.Token {
			t.Fatal("raw token stored")
		}
	}
	// Looking up by the hash as if it were a token fails.
	if _, _, err := e.s.Session(ctx, l.Session.TokenHash); !errors.Is(err, core.ErrNotFound) {
		t.Fatalf("err %v", err)
	}
	sess, u, err := e.s.Session(ctx, l.Token)
	if err != nil || u.ID != l.User.ID || sess.UserID != u.ID {
		t.Fatalf("%v", err)
	}
	if _, _, err := e.s.Session(ctx, ""); !errors.Is(err, core.ErrNotFound) {
		t.Fatalf("empty token: %v", err)
	}
}

func TestSessionExpiryAndSlidingLastSeen(t *testing.T) {
	e := newEnv(t)
	ttl := e.cfg.Current().Sessions.TTL
	l, _ := e.s.Login(ctx, "alice", "alicepw", ip1)

	e.clock.Advance(30 * time.Second)
	sess, _, err := e.s.Session(ctx, l.Token)
	if err != nil || !sess.LastSeenAt.Equal(l.Session.CreatedAt) {
		t.Fatalf("touched too early: %v %v", err, sess.LastSeenAt)
	}
	e.clock.Advance(40 * time.Second)
	sess, _, _ = e.s.Session(ctx, l.Token)
	if !sess.LastSeenAt.Equal(e.clock.Now()) {
		t.Fatalf("not touched: %v", sess.LastSeenAt)
	}
	stored, _ := e.sess.Get(ctx, l.Session.TokenHash)
	if !stored.LastSeenAt.Equal(e.clock.Now()) {
		t.Fatal("last seen not persisted")
	}

	e.clock.Set(l.Session.ExpiresAt.Add(-time.Second))
	if _, _, err := e.s.Session(ctx, l.Token); err != nil {
		t.Fatalf("before expiry: %v", err)
	}
	e.clock.Set(l.Session.ExpiresAt)
	if _, _, err := e.s.Session(ctx, l.Token); !errors.Is(err, core.ErrExpired) {
		t.Fatalf("at expiry: %v (ttl %v)", err, ttl)
	}
	if e.sess.count() != 0 {
		t.Fatal("expired session not deleted")
	}
	if _, _, err := e.s.Session(ctx, l.Token); !errors.Is(err, core.ErrNotFound) {
		t.Fatalf("after delete: %v", err)
	}
}

func TestPurgeExpired(t *testing.T) {
	e := newEnv(t)
	_, _ = e.s.Login(ctx, "alice", "alicepw", ip1)
	e.clock.Advance(e.cfg.Current().Sessions.TTL / 2)
	_, _ = e.s.Login(ctx, "alice", "alicepw", ip1)
	e.clock.Advance(e.cfg.Current().Sessions.TTL/2 + time.Second)
	n, err := e.s.PurgeExpired(ctx)
	if err != nil || n != 1 || e.sess.count() != 1 {
		t.Fatalf("n=%d err=%v left=%d", n, err, e.sess.count())
	}
}

func TestLogout(t *testing.T) {
	e := newEnv(t)
	l, _ := e.s.Login(ctx, "alice", "alicepw", ip1)
	if err := e.s.Logout(ctx, l.Token); err != nil {
		t.Fatal(err)
	}
	if _, _, err := e.s.Session(ctx, l.Token); !errors.Is(err, core.ErrNotFound) {
		t.Fatalf("err %v", err)
	}
	if err := e.s.Logout(ctx, l.Token); err != nil {
		t.Fatalf("second logout: %v", err)
	}
	if err := e.s.Logout(ctx, "unknown"); err != nil {
		t.Fatal(err)
	}
	if ev := e.audit.OfType(core.AuditLogout); len(ev) != 1 || ev[0].Username != "alice" {
		t.Fatalf("audit %+v", ev)
	}
}

func TestEnvAdminPromotion(t *testing.T) {
	e := newEnv(t)
	e.cfg.Update(func(c *core.Config) { c.Bootstrap.Admins = []string{"Alice", "carol"} })
	l, err := e.s.Login(ctx, "alice", "alicepw", ip1)
	if err != nil || l.User.Role != core.RoleAdmin {
		t.Fatalf("%v %+v", err, l)
	}
	// Demoted in the store, promoted again on the next login.
	_ = e.users.SetRole(ctx, l.User.ID, core.RoleNormal)
	l, _ = e.s.Login(ctx, "alice", "alicepw", ip1)
	if l.User.Role != core.RoleAdmin {
		t.Fatal("not re-promoted")
	}
	// Existing sessions are not promoted behind the user's back, and an
	// unlisted user stays normal.
	e.dir.SetUser("bob", "bobpw")
	l, _ = e.s.Login(ctx, "bob", "bobpw", ip1)
	if l.User.Role != core.RoleNormal {
		t.Fatal("bob promoted")
	}
	// Removal from the list does not demote.
	e.cfg.Update(func(c *core.Config) { c.Bootstrap.Admins = nil })
	l, _ = e.s.Login(ctx, "alice", "alicepw", ip1)
	if l.User.Role != core.RoleAdmin {
		t.Fatal("demoted by list removal")
	}
}

func TestBlockedUser(t *testing.T) {
	e := newEnv(t)
	l, _ := e.s.Login(ctx, "alice", "alicepw", ip1)
	_ = e.users.SetBlocked(ctx, l.User.ID, true)
	// Existing session sees it immediately.
	_, u, err := e.s.Session(ctx, l.Token)
	if err != nil || !u.Blocked || u.Can(core.RoleNormal) {
		t.Fatalf("%v %+v", err, u)
	}
	// Login is still allowed; callers check Blocked.
	l2, err := e.s.Login(ctx, "alice", "alicepw", ip1)
	if err != nil || !l2.User.Blocked {
		t.Fatalf("%v %+v", err, l2)
	}
}

func TestBlockedAdminStaysBlockedOnLogin(t *testing.T) {
	// A promoted LDAP admin can be blocked: admin + blocked is valid.
	e := newEnv(t)
	e.cfg.Update(func(c *core.Config) { c.Bootstrap.Admins = []string{"alice"} })
	l, _ := e.s.Login(ctx, "alice", "alicepw", ip1)
	_ = e.users.SetBlocked(ctx, l.User.ID, true)
	l, _ = e.s.Login(ctx, "alice", "alicepw", ip1)
	if !l.User.Blocked || l.User.Role != core.RoleAdmin {
		t.Fatalf("%+v", l.User)
	}
}

func TestLocalAdminPlainAndBcrypt(t *testing.T) {
	hash, err := bcrypt.GenerateFromPassword([]byte("s3cret"), bcrypt.MinCost)
	if err != nil {
		t.Fatal(err)
	}
	for name, stored := range map[string]string{"plain": "s3cret", "bcrypt": string(hash)} {
		t.Run(name, func(t *testing.T) {
			e := newEnv(t)
			e.cfg.Update(func(c *core.Config) {
				c.Bootstrap.LocalAdminUser = "Root"
				c.Bootstrap.LocalAdminPassword = stored
			})
			e.dir.SetDown(true) // works with LDAP down
			e.cfg.Update(func(c *core.Config) { c.LDAP.URL = "" })
			l, err := e.s.Login(ctx, "root", "s3cret", ip1)
			if err != nil {
				t.Fatal(err)
			}
			if !l.User.Local || l.User.Role != core.RoleAdmin || l.User.Username != "root" {
				t.Fatalf("%+v", l.User)
			}
			if e.dir.Calls() != 0 {
				t.Fatal("directory consulted for local admin")
			}
			for _, bad := range []string{"S3cret", "s3cret ", "x", ""} {
				if _, err := e.s.Login(ctx, "root", bad, ip2); err == nil {
					t.Fatalf("accepted %q", bad)
				}
			}
			// Cannot be blocked: a blocked flag is cleared at login.
			_ = e.users.SetBlocked(ctx, l.User.ID, true)
			_ = e.users.SetRole(ctx, l.User.ID, core.RoleNormal)
			l, err = e.s.Login(ctx, "root", "s3cret", ip1)
			if err != nil || l.User.Blocked || l.User.Role != core.RoleAdmin {
				t.Fatalf("%v %+v", err, l)
			}
			stored, _ := e.users.Get(ctx, l.User.ID)
			if stored.Blocked || stored.Role != core.RoleAdmin {
				t.Fatal("not persisted")
			}
		})
	}
}

func TestLocalAdminDisabledWithoutPassword(t *testing.T) {
	e := newEnv(t)
	e.cfg.Update(func(c *core.Config) { c.Bootstrap.LocalAdminUser = "root" })
	if _, err := e.s.Login(ctx, "root", "", ip1); err == nil {
		t.Fatal("empty password accepted")
	}
}

func TestLocalAdminAndLDAPUserSameNameAreDistinct(t *testing.T) {
	e := newEnv(t)
	e.cfg.Update(func(c *core.Config) {
		c.Bootstrap.LocalAdminUser = "alice"
		c.Bootstrap.LocalAdminPassword = "localpw"
	})
	a, err := e.s.Login(ctx, "alice", "localpw", ip1)
	if err != nil || !a.User.Local {
		t.Fatalf("%v %+v", err, a)
	}
	b, err := e.s.Login(ctx, "alice", "alicepw", ip1)
	if err != nil || b.User.Local || b.User.ID == a.User.ID || b.User.Role != core.RoleNormal {
		t.Fatalf("%v %+v", err, b)
	}
}

func TestDirectoryDown(t *testing.T) {
	e := newEnv(t)
	e.cfg.Update(func(c *core.Config) {
		c.Bootstrap.LocalAdminUser = "root"
		c.Bootstrap.LocalAdminPassword = "s3cret"
	})
	l, _ := e.s.Login(ctx, "alice", "alicepw", ip1)
	e.dir.SetDown(true)

	// Existing session keeps working, with no directory call.
	calls := e.dir.Calls()
	if _, _, err := e.s.Session(ctx, l.Token); err != nil {
		t.Fatal(err)
	}
	if e.dir.Calls() != calls {
		t.Fatal("Session consulted the directory")
	}
	// New LDAP logins fail with unavailable.
	if _, err := e.s.Login(ctx, "alice", "alicepw", ip1); !errors.Is(err, core.ErrDirectoryUnavailable) {
		t.Fatalf("err %v", err)
	}
	if ev := e.audit.OfType(core.AuditError); len(ev) != 1 {
		t.Fatalf("error audit %+v", ev)
	}
	// Local admin works.
	if _, err := e.s.Login(ctx, "root", "s3cret", ip1); err != nil {
		t.Fatal(err)
	}
	// And LDAP recovers.
	e.dir.SetDown(false)
	if _, err := e.s.Login(ctx, "alice", "alicepw", ip1); err != nil {
		t.Fatal(err)
	}
}

func TestThrottle(t *testing.T) {
	e := newEnv(t)
	for i := 0; i < throttleMax; i++ {
		if _, err := e.s.Login(ctx, "alice", "bad", ip1); !errors.Is(err, core.ErrInvalidCredentials) || AsThrottled(err) != nil {
			t.Fatalf("attempt %d: %v", i, err)
		}
	}
	calls := e.dir.Calls()
	// Even the right password is refused now, without reaching the directory.
	_, err := e.s.Login(ctx, "alice", "alicepw", ip1)
	th := AsThrottled(err)
	if th == nil || !errors.Is(err, core.ErrInvalidCredentials) || th.RetryAfter <= 0 || th.RetryAfter > throttleWindow {
		t.Fatalf("err %v", err)
	}
	if e.dir.Calls() != calls {
		t.Fatal("throttled attempt reached directory")
	}
	// Other source and other user are unaffected.
	if _, err := e.s.Login(ctx, "alice", "alicepw", ip2); err != nil {
		t.Fatalf("other ip: %v", err)
	}
	e.dir.SetUser("bob", "bobpw")
	if _, err := e.s.Login(ctx, "bob", "bobpw", ip1); err != nil {
		t.Fatalf("other user: %v", err)
	}
	// Window passes.
	e.clock.Advance(throttleWindow + time.Second)
	if _, err := e.s.Login(ctx, "alice", "alicepw", ip1); err != nil {
		t.Fatalf("after window: %v", err)
	}
	// Success resets the counter.
	for i := 0; i < throttleMax-1; i++ {
		_, _ = e.s.Login(ctx, "alice", "bad", ip1)
	}
	_, _ = e.s.Login(ctx, "alice", "alicepw", ip1)
	for i := 0; i < throttleMax-1; i++ {
		if _, err := e.s.Login(ctx, "alice", "bad", ip1); AsThrottled(err) != nil {
			t.Fatal("counter not reset by success")
		}
	}
	// Throttled attempts did not extend the lockout.
	if got := len(e.throttleFails("alice", ip1)); got != throttleMax-1 {
		t.Fatalf("fails %d", got)
	}
}

func (e *env) throttleFails(user string, ip netip.Addr) []time.Time {
	e.s.throttle.mu.Lock()
	defer e.s.throttle.mu.Unlock()
	return e.s.throttle.m[throttleKey{user, ip}]
}

func TestThrottleAlsoGuardsLocalAdmin(t *testing.T) {
	e := newEnv(t)
	e.cfg.Update(func(c *core.Config) {
		c.Bootstrap.LocalAdminUser = "root"
		c.Bootstrap.LocalAdminPassword = "s3cret"
	})
	for i := 0; i < throttleMax; i++ {
		_, _ = e.s.Login(ctx, "root", "guess", ip1)
	}
	if _, err := e.s.Login(ctx, "root", "s3cret", ip1); AsThrottled(err) == nil {
		t.Fatalf("local admin not throttled: %v", err)
	}
}

func TestDirectoryDownNotCountedAsGuess(t *testing.T) {
	e := newEnv(t)
	e.dir.SetDown(true)
	for i := 0; i < throttleMax+2; i++ {
		if _, err := e.s.Login(ctx, "alice", "alicepw", ip1); !errors.Is(err, core.ErrDirectoryUnavailable) {
			t.Fatalf("attempt %d: %v", i, err)
		}
	}
}

func TestAuditLoginNeverContainsPassword(t *testing.T) {
	e := newEnv(t)
	_, _ = e.s.Login(ctx, "alice", "alicepw", ip1)
	_, _ = e.s.Login(ctx, "alice", "hunter2-wrong", ip1)
	evs := e.audit.OfType(core.AuditLogin)
	if len(evs) != 2 {
		t.Fatalf("events %+v", evs)
	}
	if evs[0].Result != core.AuditResultOK || evs[0].Username != "alice" || evs[0].SourceIP != "192.0.2.10" {
		t.Fatalf("success %+v", evs[0])
	}
	if evs[1].Result != core.AuditResultFailed || evs[1].Reason != "invalid_credentials" {
		t.Fatalf("failure %+v", evs[1])
	}
	for _, ev := range e.audit.Events() {
		if s := ev.Detail + ev.Reason + ev.Username; strings.Contains(s, "alicepw") || strings.Contains(s, "hunter2") {
			t.Fatalf("password in audit: %+v", ev)
		}
	}
}
