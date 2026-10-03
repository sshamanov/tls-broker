package ui

import (
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"tls-broker/internal/core"
	"tls-broker/internal/names"
)

type pageSpec struct {
	path string
	min  core.Role // lowest role allowed; "" = also blocked users
}

var allPages = []pageSpec{
	{"/ui/", ""},
	{"/ui/grants", ""},
	{"/ui/audit", ""},
	{"/ui/certificates", core.RoleNormal},
	{"/ui/admin/users", core.RoleAdmin},
	{"/ui/admin/grants", core.RoleAdmin},
	{"/ui/admin/config", core.RoleAdmin},
	{"/ui/admin/secrets", core.RoleAdmin},
	{"/ui/admin/providers", core.RoleAdmin},
}

func TestPagesPerRole(t *testing.T) {
	e := newEnv(t)
	e.sched.SetSnapshot(core.SchedulerSnapshot{Providers: []core.ProviderSnapshot{{Name: "letsencrypt", State: core.ProviderState{Name: "letsencrypt", Health: core.ProviderHealthy}, SlotsTotal: 4,
		Budgets: []core.BudgetUsage{{Kind: core.BudgetNewOrder, Used: 3, Limit: 200, Window: 3 * time.Hour}}}}})
	admin := e.login("alice")
	bob := e.login("bob")
	carol := e.loginAs("carol", core.RoleWildcardAllowed)
	dave := e.login("dave")
	e.store.Users().SetBlocked(bg, e.userID("dave"), true)
	_ = admin

	roles := map[string]struct {
		c    *client
		rank core.Role
		blk  bool
	}{"admin": {admin, core.RoleAdmin, false}, "normal": {bob, core.RoleNormal, false}, "wildcard": {carol, core.RoleWildcardAllowed, false}, "blocked": {dave, core.RoleNormal, true}}
	for name, r := range roles {
		for _, p := range allPages {
			res := r.c.get(p.path)
			allowed := p.min == "" || (!r.blk && r.rank.AtLeast(p.min))
			if allowed {
				if res.code != 200 {
					t.Errorf("%s %s: %d", name, p.path, res.code)
				}
				if !strings.Contains(res.body, `<nav>`) || !strings.Contains(res.body, "alice") && name == "admin" {
					t.Errorf("%s %s: layout missing", name, p.path)
				}
			} else if res.code != 403 {
				t.Errorf("%s %s: %d, want 403", name, p.path, res.code)
			}
			if res.hdr.Get("Cache-Control") != "no-store" {
				t.Errorf("%s: Cache-Control %q", p.path, res.hdr.Get("Cache-Control"))
			}
		}
	}
	// Blocked users see the banner.
	see(t, dave.get("/ui/grants"), "Your account is blocked")
	see(t, bob.get("/ui/"), "bob", "normal")
}

func TestAnonymousAndMethods(t *testing.T) {
	e := newEnv(t)
	c := e.client()
	for _, p := range allPages {
		r := c.get(p.path)
		code(t, r, 303)
		if !strings.HasPrefix(r.hdr.Get("Location"), "/ui/login?next=") {
			t.Errorf("%s: location %q", p.path, r.hdr.Get("Location"))
		}
	}
	code(t, c.post("/ui/grants", url.Values{"prefix": {"10.0.0.1"}}), 401)
	code(t, c.post("/ui/admin/config/activate", url.Values{}), 401)
	code(t, c.get("/ui/logout"), 405)
	code(t, c.post("/ui/audit", nil), 405)
	code(t, c.get("/ui/login"), 200)
	// Static assets need no login and are cacheable.
	r := c.get("/ui/static/ui.css")
	code(t, r, 200)
	if cc := r.hdr.Get("Cache-Control"); !strings.Contains(cc, "max-age=31536000") {
		t.Errorf("static Cache-Control %q", cc)
	}
	// Security headers.
	h := c.get("/ui/login").hdr
	for _, k := range []string{"Content-Security-Policy", "X-Frame-Options", "X-Content-Type-Options", "Referrer-Policy"} {
		if h.Get(k) == "" {
			t.Errorf("missing header %s", k)
		}
	}
	if csp := h.Get("Content-Security-Policy"); strings.Contains(csp, "unsafe-inline") || strings.Contains(csp, "unsafe-eval") {
		t.Errorf("csp %q", csp)
	}
	r = c.get("/ui/login")
	if strings.Contains(r.body, "onclick=") || strings.Contains(r.body, "<script>") {
		t.Error("inline script in page")
	}
}

func TestRoleGatedPosts(t *testing.T) {
	e := newEnv(t)
	bob := e.login("bob")
	for _, p := range []string{"/ui/admin/users/1/block", "/ui/admin/grants/1/delete", "/ui/admin/config/activate", "/ui/admin/config/rollback", "/ui/admin/secrets", "/ui/admin/secrets/delete", "/ui/admin/config/test-ldap", "/ui/certificates/rotate"} {
		code(t, bob.act(p, url.Values{"name": {"x"}, "value": {"y"}}), 403)
	}
	if n, _ := e.secrets.List(bg); len(n) != 0 {
		t.Errorf("secret written by normal user: %v", n)
	}
}

func TestLogin(t *testing.T) {
	e := newEnv(t)
	c := e.client()
	r := c.post("/ui/login", url.Values{"username": {"bob"}, "password": {"nope"}})
	code(t, r, 401)
	see(t, r, "Invalid username or password")

	e.dir.SetDown(true)
	r = c.post("/ui/login", url.Values{"username": {"bob"}, "password": {"bob-pw"}})
	code(t, r, 503)
	see(t, r, "LDAP directory is unavailable")
	// The local admin still works with LDAP down.
	r = c.post("/ui/login", url.Values{"username": {"root"}, "password": {"rootpw"}, "next": {"/ui/admin/config"}})
	code(t, r, 303)
	if r.hdr.Get("Location") != "/ui/admin/config" {
		t.Errorf("next: %q", r.hdr.Get("Location"))
	}
	code(t, c.get("/ui/admin/users"), 200)
	e.dir.SetDown(false)

	// Open redirects are refused.
	c2 := e.client()
	r = c2.post("/ui/login", url.Values{"username": {"bob"}, "password": {"bob-pw"}, "next": {"//evil.example"}})
	if r.hdr.Get("Location") != "/ui/" {
		t.Errorf("open redirect: %q", r.hdr.Get("Location"))
	}
	// Logout needs CSRF, then ends the session.
	code(t, c2.post("/ui/logout", nil), 403)
	code(t, c2.get("/ui/grants"), 200)
	code(t, c2.act("/ui/logout", nil), 303)
	code(t, c2.get("/ui/grants"), 303)
	// Cross-site login posts are refused.
	req, _ := http.NewRequest("POST", e.srv.URL+"/ui/login", strings.NewReader("username=bob&password=bob-pw"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Sec-Fetch-Site", "cross-site")
	code(t, e.client().send(req), 403)
}

func TestCSRF(t *testing.T) {
	e := newEnv(t)
	bob := e.login("bob")
	code(t, bob.post("/ui/grants", url.Values{"prefix": {"10.0.0.1"}}), 403)
	code(t, bob.post("/ui/grants", url.Values{"prefix": {"10.0.0.1"}, "csrf_token": {"wrong"}}), 403)
	if g, _ := e.store.Grants().List(bg, 0); len(g) != 0 {
		t.Fatalf("grant created without CSRF: %v", g)
	}
	code(t, bob.act("/ui/grants", url.Values{"prefix": {"10.0.0.1"}}), 303)
	admin := e.login("alice")
	code(t, admin.post("/ui/admin/secrets", url.Values{"name": {"x"}, "value": {"y"}}), 403)
}

func TestGrantRules(t *testing.T) {
	e := newEnv(t)
	bob := e.login("bob")
	carol := e.loginAs("carol", core.RoleWildcardAllowed)
	admin := e.login("alice")

	// Normal user: ordinary grant ok, wildcard refused.
	code(t, bob.act("/ui/grants", url.Values{"prefix": {"10.1.2.3"}, "note": {"<b>laptop</b>"}}), 303)
	r := bob.act("/ui/grants", url.Values{"prefix": {"10.1.3.0/24"}, "wildcard": {"true"}})
	code(t, r, 403)
	see(t, r, "may not create wildcard grants")
	// Invalid input.
	for _, bad := range []string{"nonsense", "2001:db8::1", "10.0.0.0/33", "0.0.0.0/0", "::ffff:10.0.0.1"} {
		code(t, bob.act("/ui/grants", url.Values{"prefix": {bad}}), 400)
	}
	gs, _ := e.store.Grants().List(bg, e.userID("bob"))
	if len(gs) != 1 || gs[0].Prefix.String() != "10.1.2.3/32" || !gs[0].Enabled || gs[0].Wildcard {
		t.Fatalf("grants: %+v", gs)
	}
	page := bob.get("/ui/grants")
	see(t, page, "&lt;b&gt;laptop&lt;/b&gt;")
	lacks(t, page, "<b>laptop</b>", `name="wildcard"`)

	// CIDR is masked; wildcard allowed for wildcard_allowed and admin.
	code(t, carol.act("/ui/grants", url.Values{"prefix": {"10.9.9.9/24"}, "wildcard": {"true"}}), 303)
	code(t, admin.act("/ui/grants", url.Values{"prefix": {"10.8.0.0/16"}, "wildcard": {"true"}}), 303)
	cg, _ := e.store.Grants().List(bg, e.userID("carol"))
	if len(cg) != 1 || cg[0].Prefix.String() != "10.9.9.0/24" || !cg[0].Wildcard {
		t.Fatalf("carol: %+v", cg)
	}
	see(t, carol.get("/ui/grants"), `name="wildcard"`)

	// Disable / enable / delete own grant.
	id := gs[0].ID
	path := "/ui/grants/" + itoa(id)
	code(t, bob.act(path+"/disable", nil), 303)
	if g, _ := e.store.Grants().Get(bg, id); g.Enabled {
		t.Error("still enabled")
	}
	code(t, bob.act(path+"/enable", nil), 303)
	if g, _ := e.store.Grants().Get(bg, id); !g.Enabled {
		t.Error("not enabled")
	}
	// Someone else's grant is invisible to a normal user.
	code(t, bob.act("/ui/grants/"+itoa(cg[0].ID)+"/delete", nil), 404)
	code(t, bob.act(path+"/explode", nil), 404)
	code(t, bob.act(path+"/delete", nil), 303)
	if _, err := e.store.Grants().Get(bg, id); !isNotFound(err) {
		t.Errorf("not deleted: %v", err)
	}
	// Admin sees and manages everyone's grants.
	ag := admin.get("/ui/admin/grants")
	see(t, ag, "carol", "10.9.9.0/24", "10.8.0.0/16")
	code(t, admin.act("/ui/admin/grants/"+itoa(cg[0].ID)+"/disable", nil), 303)
	if g, _ := e.store.Grants().Get(bg, cg[0].ID); g.Enabled {
		t.Error("admin disable failed")
	}
	code(t, admin.act("/ui/admin/grants/"+itoa(cg[0].ID)+"/delete", nil), 303)
	code(t, bob.act("/ui/admin/grants/1/delete", nil), 403)

	// Audit: grant changes are recorded, admin-visible only.
	evs, _ := e.audit.Query(bg, core.AuditQuery{IncludeAdmin: true, Type: core.AuditGrantChange})
	if len(evs) < 5 {
		t.Errorf("grant audit events: %d", len(evs))
	}
	pub, _ := e.audit.Query(bg, core.AuditQuery{Type: core.AuditGrantChange})
	if len(pub) != 0 {
		t.Errorf("grant changes leaked to public view: %d", len(pub))
	}
}

func itoa(n int64) string { return strconv.FormatInt(n, 10) }

func fmtI(n int64) string { return itoa(n) }

func TestBlockedUserCannotCreate(t *testing.T) {
	e := newEnv(t)
	bob := e.login("bob")
	admin := e.login("alice")
	bid := e.userID("bob")
	code(t, bob.act("/ui/grants", url.Values{"prefix": {"10.0.0.1"}}), 303)
	g, _ := e.store.Grants().List(bg, bid)

	// Block takes effect immediately for the live session.
	r := admin.act("/ui/admin/users/"+itoa(bid)+"/block", nil)
	code(t, r, 303)
	see(t, admin.follow(r), "bob: blocked=true")
	r = bob.act("/ui/grants", url.Values{"prefix": {"10.0.0.2"}})
	code(t, r, 403)
	code(t, bob.act("/ui/grants/"+itoa(g[0].ID)+"/disable", nil), 403)
	code(t, bob.get("/ui/certificates"), 403)
	page := bob.get("/ui/grants")
	code(t, page, 200)
	see(t, page, "Your account is blocked", "10.0.0.1")
	lacks(t, page, "New grant")
	code(t, bob.get("/ui/audit"), 200)
	if g2, _ := e.store.Grants().List(bg, bid); len(g2) != 1 || !g2[0].Enabled {
		t.Errorf("blocked user changed grants: %+v", g2)
	}
	// The existing grant stays (grants are independent of the owner).

	code(t, admin.act("/ui/admin/users/"+itoa(bid)+"/unblock", nil), 303)
	code(t, bob.act("/ui/grants", url.Values{"prefix": {"10.0.0.2"}}), 303)

	// Role change applies immediately.
	r = bob.act("/ui/grants", url.Values{"prefix": {"10.0.1.0/24"}, "wildcard": {"true"}})
	code(t, r, 403)
	code(t, admin.act("/ui/admin/users/"+itoa(bid)+"/role", url.Values{"role": {"wildcard_allowed"}}), 303)
	code(t, bob.act("/ui/grants", url.Values{"prefix": {"10.0.1.0/24"}, "wildcard": {"true"}}), 303)
	code(t, admin.act("/ui/admin/users/"+itoa(bid)+"/role", url.Values{"role": {"emperor"}}), 303)
	if u, _ := e.store.Users().Get(bg, bid); u.Role != core.RoleWildcardAllowed {
		t.Errorf("role %q", u.Role)
	}

	// Local break-glass admin and self cannot be changed.
	root := e.login("root")
	_ = root
	lu, _ := e.store.Users().GetByUsername(bg, "root", true)
	r = admin.act("/ui/admin/users/"+itoa(lu.ID)+"/block", nil)
	see(t, admin.follow(r), "break-glass")
	if u, _ := e.store.Users().Get(bg, lu.ID); u.Blocked {
		t.Error("local admin blocked")
	}
	aid := e.userID("alice")
	r = admin.act("/ui/admin/users/"+itoa(aid)+"/block", nil)
	see(t, admin.follow(r), "own role")
	code(t, admin.act("/ui/admin/users/999/block", nil), 404)

	evs, _ := e.audit.Query(bg, core.AuditQuery{IncludeAdmin: true, Type: core.AuditUserChange})
	if len(evs) != 3 {
		t.Errorf("user_change events: %+v", evs)
	}
}

func TestAuditVisibility(t *testing.T) {
	e := newEnv(t)
	e.audit.Record(bg, core.AuditEvent{Type: core.AuditIssue, Visibility: core.AuditVisibilityAll, Mode: core.ModeACME, Names: []string{"public.example.com"}, Result: "ok"})
	e.audit.Record(bg, core.AuditEvent{Type: core.AuditGate, Visibility: core.AuditVisibilityAdmin, Mode: core.ModeACME, Names: []string{"secretdeny.example.com"}, Decision: "deny", Reason: "no_grant"})
	bob := e.login("bob")
	admin := e.login("alice")
	dave := e.login("dave")
	e.store.Users().SetBlocked(bg, e.userID("dave"), true)

	for _, c := range []*client{bob, dave} {
		r := c.get("/ui/audit")
		see(t, r, "public.example.com")
		lacks(t, r, "secretdeny.example.com")
		// A normal user cannot ask for the admin view.
		lacks(t, c.get("/ui/audit?scope=all&q=secretdeny"), "secretdeny.example.com")
		lacks(t, c.get("/ui/"), "secretdeny.example.com")
	}
	r := admin.get("/ui/audit")
	see(t, r, "public.example.com", "secretdeny.example.com")
	r = admin.get("/ui/audit?scope=public")
	see(t, r, "public.example.com")
	lacks(t, r, "secretdeny.example.com")
	see(t, admin.get("/ui/audit?type=gate"), "secretdeny.example.com")
	lacks(t, admin.get("/ui/audit?type=gate"), "public.example.com")
	see(t, admin.get("/ui/audit?q=SECRETDENY"), "secretdeny.example.com")
	see(t, admin.get("/ui/audit?since=junk"), "invalid")
	see(t, admin.get("/ui/"), "secretdeny.example.com")
}

func TestAuditPaging(t *testing.T) {
	e := newEnv(t)
	for i := 0; i < 70; i++ {
		e.clock.Advance(time.Second)
		e.audit.Record(bg, core.AuditEvent{Type: core.AuditIssue, Visibility: core.AuditVisibilityAll, Names: []string{"n" + fmtI(int64(i)) + ".example.com"}})
	}
	bob := e.login("bob")
	r := bob.get("/ui/audit")
	see(t, r, "n69.example.com", "Older")
	lacks(t, r, "n10.example.com")
	i := strings.Index(r.body, `href="/ui/audit?`)
	if i < 0 {
		t.Fatal("no older link")
	}
	link := strings.ReplaceAll(r.body[i+6:i+6+strings.Index(r.body[i+6:], `"`)], "&amp;", "&")
	r2 := bob.get(link)
	see(t, r2, "n19.example.com", "n0.example.com", "Newest")
	lacks(t, r2, "n69.example.com", "Older")
}

func TestDashboard(t *testing.T) {
	e := newEnv(t)
	e.caa.m["example.com"] = core.CAAStatus{Name: "example.com", WildcardProtected: false, Detail: "wide open zone"}
	e.sched.SetSnapshot(core.SchedulerSnapshot{Providers: []core.ProviderSnapshot{{Name: "letsencrypt", Open: false,
		State: core.ProviderState{Name: "letsencrypt", Health: core.ProviderLimited, RetryAfter: e.clock.Now().Add(time.Hour), LastError: "too many"}}}})
	// Seed one direct entry and one ACME certificate.
	now := e.clock.Now()
	e.store.Direct().Put(bg, &core.DirectEntry{Identifier: "svc.example.com", Generation: 1, Provider: "letsencrypt", NotBefore: now.Add(-time.Hour), NotAfter: now.Add(30 * 24 * time.Hour), RenewAt: now.Add(20 * 24 * time.Hour), CreatedAt: now, UpdatedAt: now})
	seedCert(t, e, "c1", "www.example.com")

	admin := e.login("alice")
	r := admin.get("/ui/")
	account, _ := e.ca.AccountURL(bg)
	see(t, r, "Broker accounts at providers", account, "example.com", "wide open zone", "is unprotected", "accounturi=", "LDAP is not configured", "circuit open", "too many")
	see(t, r, "<b>1</b><span>valid ACME certificates", "is rate_limited until")
	// Without a zone status source the configured hosted zone ID is shown.
	see(t, r, "<code>Z0123456789ABC</code>", "configured")
	lacks(t, r, "discovered by name", "no hosted zone")

	// The engine's view wins: a discovered ID, or why there is none.
	e.h.Zones = zonesStub{{Name: "example.com", HostedZoneID: "ZDISCOVERED", Resolved: true}}
	r = admin.get("/ui/")
	see(t, r, "<code>ZDISCOVERED</code>", "discovered by name")
	lacks(t, r, "Z0123456789ABC")
	e.h.Zones = zonesStub{{Name: "example.com", Err: "no public hosted zone named example.com"}}
	r = admin.get("/ui/")
	see(t, r, "not discovered: no public hosted zone named example.com", "Zone example.com: no hosted zone; DNS-01 fails for it")
	e.h.Zones = nil

	// Snapshot.Open means admission is open: a healthy provider shows neither
	// "circuit open" nor a dashboard warning.
	e.sched.SetSnapshot(core.SchedulerSnapshot{Providers: []core.ProviderSnapshot{{Name: "letsencrypt", Open: true,
		State: core.ProviderState{Name: "letsencrypt", Health: core.ProviderHealthy}}}})
	r = admin.get("/ui/")
	see(t, r, `<span class="badge good">healthy</span>`)
	lacks(t, r, "circuit open", "is healthy until")
	see(t, admin.get("/ui/admin/providers"), `<span class="badge good">healthy</span>`)
	lacks(t, admin.get("/ui/admin/providers"), "circuit open")

	bob := e.login("bob")
	r = bob.get("/ui/")
	lacks(t, r, account, "unprotected", "Managed zones")
	see(t, r, "valid ACME certificates", "letsencrypt")

	// LDAP untested -> test -> warning goes away.
	e.cfg.Activate(bg, []byte(goodYAML+"ldap:\n  url: ldaps://ldap.example.com:636\n  base_dn: dc=example,dc=com\n  user_filter: (uid=%s)\n"))
	see(t, admin.get("/ui/"), "LDAP has not been tested")
	e.ldap.set(errLDAPDown)
	r = admin.act("/ui/admin/config/test-ldap", nil)
	see(t, admin.follow(r), "LDAP test failed", "connection refused")
	see(t, admin.get("/ui/"), "last LDAP test")
	e.ldap.set(nil)
	see(t, admin.follow(admin.act("/ui/admin/config/test-ldap", nil)), "LDAP test succeeded")
	lacks(t, admin.get("/ui/"), "LDAP has not been tested", "last LDAP test")
	if evs, _ := e.audit.Query(bg, core.AuditQuery{IncludeAdmin: true, Type: core.AuditError}); len(evs) != 1 {
		t.Errorf("error events: %d", len(evs))
	}
}

// zonesStub is a fixed ZoneStatusSource.
type zonesStub []ZoneStatus

func (z zonesStub) ZoneStatuses() []ZoneStatus { return z }

func seedCert(t *testing.T, e *env, id, name string) {
	t.Helper()
	now := e.clock.Now()
	o := &core.Order{ID: "o-" + id, Mode: core.ModeACME, AccountID: "acct1", Names: names.MustSet(name), SourceIP: mustAddr("10.0.0.5"), Status: core.OrderReady, Prep: core.PrepIntent,
		Class: core.ClassACMEOrdinary, Provider: "letsencrypt", CreatedAt: now, ExpiresAt: now.Add(15 * time.Minute)}
	st := e.store.Orders()
	for _, err := range []error{
		st.Create(bg, o),
		st.SetUpstream(bg, o.ID, "https://ca/o/"+id, "", now.Add(time.Hour), now),
		st.SetPrepared(bg, o.ID, now),
		func() error { _, _, err := st.BeginFinalize(bg, o.ID, "h"+id, []byte("csr"), now); return err }(),
		st.Complete(bg, o.ID, &core.Certificate{ID: id, OrderID: o.ID, Mode: core.ModeACME, Names: o.Names, Provider: "letsencrypt", Serial: "0a" + id, ARICertID: "aki." + id,
			NotBefore: now.Add(-time.Hour), NotAfter: now.Add(60 * 24 * time.Hour), IssuedAt: now, ChainPEM: []byte("x")}, now),
	} {
		if err != nil {
			t.Fatal(err)
		}
	}
	if _, err := e.store.Lineages().Observe(bg, o.Names.Key(), now); err != nil {
		t.Fatal(err)
	}
}

func TestCertificates(t *testing.T) {
	rot := &rotatorStub{}
	e := newEnv(t, envOpts{rotator: rot})
	now := e.clock.Now()
	seedCert(t, e, "c1", "www.example.com")
	seedCert(t, e, "c2", "api.example.com")
	e.store.Direct().Put(bg, &core.DirectEntry{Identifier: "svc.example.com", Generation: 2, Provider: "letsencrypt", NotBefore: now.Add(-time.Hour), NotAfter: now.Add(30 * 24 * time.Hour),
		RenewAt: now.Add(20 * 24 * time.Hour), LastFetchAt: now, LastFetchIP: mustAddr("10.2.2.2"), CreatedAt: now, UpdatedAt: now, LastError: "boom", Failures: 2})
	bob := e.login("bob")
	r := bob.get("/ui/certificates")
	see(t, r, "www.example.com", "api.example.com", "svc.example.com", "10.2.2.2", "boom")
	lacks(t, r, "Rotate key")
	lacks(t, bob.get("/ui/certificates?q=api"), "www.example.com", "svc.example.com")
	see(t, bob.get("/ui/certificates?q=API"), "api.example.com")
	lacks(t, bob.get("/ui/certificates?mode=direct"), "www.example.com")
	lacks(t, bob.get("/ui/certificates?mode=acme"), "svc.example.com")
	lacks(t, bob.get("/ui/certificates?provider=other"), "www.example.com", "svc.example.com")

	admin := e.login("alice")
	see(t, admin.get("/ui/certificates"), "Rotate key")
	code(t, admin.act("/ui/certificates/rotate", url.Values{"identifier": {"svc.example.com"}}), 303)
	if len(rot.got) != 1 || rot.got[0] != "svc.example.com" {
		t.Errorf("rotated %v", rot.got)
	}
	code(t, admin.act("/ui/certificates/rotate", url.Values{"identifier": {"nope.example.com"}}), 404)

	// Without a rotator the route is a 404 and no button is shown.
	e2 := newEnv(t)
	a2 := e2.login("alice")
	code(t, a2.act("/ui/certificates/rotate", url.Values{"identifier": {"x"}}), 404)

	// Expired certificates are hidden unless asked for.
	e.clock.Advance(100 * 24 * time.Hour)
	bob = e.login("bob")
	lacks(t, bob.get("/ui/certificates?mode=acme"), "www.example.com")
	see(t, bob.get("/ui/certificates?mode=acme&expired=1"), "www.example.com")
}

func TestConfigFlow(t *testing.T) {
	e := newEnv(t)
	admin := e.login("alice")
	r := admin.get("/ui/admin/config")
	see(t, r, "Active generation: <b>2</b>", "external_url: https://broker.example.com", "Generations")

	// Invalid YAML: problems with field paths, nothing stored.
	bad := "zones:\n  - name: not a zone!\n    hosted_zone_id: nope\n"
	r = admin.act("/ui/admin/config/validate", url.Values{"yaml": {bad}})
	code(t, r, 200)
	see(t, r, "Invalid", "zones[0]", "not a zone!")
	r = admin.act("/ui/admin/config/activate", url.Values{"yaml": {bad}})
	code(t, r, 422)
	see(t, r, "Not activated", "zones[0]")
	if e.cfg.Current().Generation != 2 {
		t.Error("invalid config activated")
	}

	// Valid: validate then activate (CRLF from the browser is normalized).
	next := strings.ReplaceAll(goodYAML+"sessions:\n  ttl: 48h\n  cookie_secure: true\n", "\n", "\r\n")
	see(t, admin.act("/ui/admin/config/validate", url.Values{"yaml": {next}}), "Valid: this configuration can be activated")
	r = admin.act("/ui/admin/config/activate", url.Values{"yaml": {next}})
	code(t, r, 303)
	see(t, admin.follow(r), "Generation 3 is now active", "Active generation: <b>3</b>")
	if e.cfg.Current().Sessions.TTL != 48*time.Hour {
		t.Error("not active")
	}
	// Missing secrets are reported.
	r = admin.act("/ui/admin/config/validate", url.Values{"yaml": {goodYAML + "route53:\n  access_key_id_secret: r53-id\n  secret_access_key_secret: r53-key\n"}})
	see(t, r, "r53-id", "does not exist")

	// History and rollback.
	r = admin.get("/ui/admin/config")
	see(t, r, "active", "Rollback")
	r = admin.act("/ui/admin/config/rollback", url.Values{"gen": {"2"}})
	see(t, admin.follow(r), "Rolled back")
	if e.cfg.Current().Sessions.TTL == 48*time.Hour {
		t.Error("rollback did not apply")
	}
	see(t, admin.get("/ui/admin/config?gen=3"), "ttl: 48h", "Editing generation 3")
	see(t, admin.follow(admin.act("/ui/admin/config/rollback", url.Values{"gen": {"99"}})), "does not exist")
	code(t, admin.get("/ui/admin/config?gen=99"), 303)

	// LDAP change is tested on validate and blocks activation when it fails.
	ldapYAML := goodYAML + "ldap:\n  url: ldaps://ldap.example.com:636\n  base_dn: dc=example,dc=com\n  user_filter: (uid=%s)\n"
	e.ldap.set(errLDAPDown)
	r = admin.act("/ui/admin/config/activate", url.Values{"yaml": {ldapYAML}})
	code(t, r, 422)
	see(t, r, "LDAP test failed", "connection refused")
	e.ldap.set(nil)
	code(t, admin.act("/ui/admin/config/activate", url.Values{"yaml": {ldapYAML}}), 303)

	evs, _ := e.audit.Query(bg, core.AuditQuery{IncludeAdmin: true, Type: core.AuditConfigChange})
	if len(evs) != 3 {
		t.Errorf("config_change events: %d", len(evs))
	}
}

func TestSecrets(t *testing.T) {
	e := newEnv(t)
	admin := e.login("alice")
	// The configuration references secrets that do not exist yet.
	e.cfg.Activate(bg, []byte(goodYAML)) // keep generation sane
	const value = "SUPER-S3CR3T-VALUE-123"

	r := admin.act("/ui/admin/secrets", url.Values{"name": {"Bad Name"}, "value": {value}})
	see(t, admin.follow(r), "Secret names use")
	r = admin.act("/ui/admin/secrets", url.Values{"name": {"provider-account-key.letsencrypt"}, "value": {value}})
	see(t, admin.follow(r), "belong to the broker")
	r = admin.act("/ui/admin/secrets", url.Values{"name": {"route53-id"}, "value": {""}})
	see(t, admin.follow(r), "empty")

	r = admin.act("/ui/admin/secrets", url.Values{"name": {"route53-id"}, "value": {value + "\r\n"}})
	see(t, admin.follow(r), "Secret route53-id saved")
	got, _ := e.secrets.Get(bg, "route53-id")
	if string(got) != value {
		t.Errorf("stored %q", got)
	}
	e.secrets.Put(bg, "provider-account-key.letsencrypt", []byte("PRIVATE-KEY-MATERIAL"))

	// Reference it from the config: present vs missing.
	y := goodYAML + "route53:\n  access_key_id_secret: route53-id\n  secret_access_key_secret: route53-key\n"
	if _, chk, _ := e.cfg.Activate(bg, []byte(y)); chk.OK() {
		t.Fatal("activation should fail for the missing secret")
	}
	e.secrets.Put(bg, "route53-key", []byte(value+"-2"))
	if _, chk, err := e.cfg.Activate(bg, []byte(y)); err != nil || !chk.OK() {
		t.Fatal(err, chk)
	}
	e.secrets.Delete(bg, "route53-key")
	r = admin.get("/ui/admin/secrets")
	see(t, r, "route53-id", "route53.secret_access_key_secret", "missing", "managed by the broker", "provider-account-key.letsencrypt")
	e.secrets.Put(bg, "route53-key", []byte(value+"-2"))

	// No page ever shows a secret value.
	for _, p := range allPages {
		lacks(t, admin.get(p.path), value, "PRIVATE-KEY-MATERIAL")
	}
	for _, c := range []*client{admin} {
		for _, p := range []string{"/ui/admin/secrets", "/ui/admin/config"} {
			lacks(t, c.get(p), value)
		}
	}
	// The set response and flash contain no value either.
	r = admin.act("/ui/admin/secrets", url.Values{"name": {"other"}, "value": {value}})
	lacks(t, r, value)
	lacks(t, admin.follow(r), value)

	// Delete: warns when referenced; broker-owned names are refused.
	r = admin.act("/ui/admin/secrets/delete", url.Values{"name": {"route53-key"}})
	see(t, admin.follow(r), "still refers to it")
	r = admin.act("/ui/admin/secrets/delete", url.Values{"name": {"provider-account-key.letsencrypt"}})
	see(t, admin.follow(r), "cannot be deleted")
	if _, err := e.secrets.Get(bg, "provider-account-key.letsencrypt"); err != nil {
		t.Error("reserved secret deleted")
	}
	if _, err := e.secrets.Get(bg, "route53-key"); !isNotFound(err) {
		t.Errorf("not deleted: %v", err)
	}

	// Audit entries name the secret, never the value.
	evs, _ := e.audit.Query(bg, core.AuditQuery{IncludeAdmin: true, Contains: "secret"})
	if len(evs) == 0 {
		t.Error("no secret audit events")
	}
	for _, ev := range evs {
		if strings.Contains(ev.Detail, value) {
			t.Errorf("secret in audit: %+v", ev)
		}
	}
}

func TestProvidersPage(t *testing.T) {
	e := newEnv(t)
	e.sched.SetSnapshot(core.SchedulerSnapshot{Providers: []core.ProviderSnapshot{{Name: "letsencrypt", Open: false, SlotsTotal: 4, SlotsInUse: 1,
		State:   core.ProviderState{Name: "letsencrypt", Health: core.ProviderUnavailable, RetryAfter: e.clock.Now().Add(10 * time.Minute), Failures: 3, LastError: "503 upstream"},
		Budgets: []core.BudgetUsage{{Kind: core.BudgetNewOrder, Used: 150, Limit: 200, Window: 3 * time.Hour}}}}})
	r := e.login("alice").get("/ui/admin/providers")
	account, _ := e.ca.AccountURL(bg)
	see(t, r, "letsencrypt", "503 upstream", "150 / 200", "10m", account, "https://acme.example/dir", "circuit open")
	lacks(t, r, "Reset")
}

func TestBanners(t *testing.T) {
	e := newEnv(t, envOpts{banners: []string{"DNS gate is mocked: <dev>"}})
	// Shown before login and on every page after it, escaped.
	see(t, e.client().get("/ui/login"), "DNS gate is mocked: &lt;dev&gt;")
	bob := e.login("bob")
	see(t, bob.get("/ui/"), "DNS gate is mocked")
	see(t, bob.get("/ui/grants"), "DNS gate is mocked")

	lacks(t, newEnv(t).client().get("/ui/login"), "DNS gate is mocked")
}
