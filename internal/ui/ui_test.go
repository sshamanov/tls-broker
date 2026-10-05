package ui

import (
	"context"
	"fmt"
	"net/http"
	"net/netip"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"tls-broker/internal/auth"
	"tls-broker/internal/core"
	"tls-broker/internal/core/coretest"
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
	{"/ui/docs", ""},
	{"/ui/docs/acme-proxy", ""},
	{"/ui/certificates", core.RoleNormal},
	{"/ui/admin/users", core.RoleAdmin},
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
				if !strings.Contains(res.body, `<nav class="nav" aria-label="Main">`) || !strings.Contains(res.body, "alice") && name == "admin" {
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
	see(t, bob.get("/ui/"), "<b>bob</b><span>user</span>")
	see(t, carol.get("/ui/"), "<b>carol</b><span>user with wildcards</span>")
	see(t, admin.get("/ui/"), "<b>alice</b><span>administrator</span>", `id="nav-admin">Administration</div>`)
	lacks(t, bob.get("/ui/"), "Administration")
	see(t, dave.get("/ui/"), "<b>dave</b><span>Blocked</span>")
	// The page in the navigation is marked for assistive technology.
	see(t, bob.get("/ui/grants"), `<a href="/ui/grants" aria-current="page">Client access</a>`)
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
	if csp := h.Get("Content-Security-Policy"); !strings.Contains(csp, "font-src 'self'") || !strings.Contains(csp, "default-src 'none'") {
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
	for _, p := range []string{"/ui/admin/users/1/block", "/ui/admin/config/activate", "/ui/admin/config/rollback", "/ui/admin/secrets", "/ui/admin/secrets/delete", "/ui/admin/config/test-ldap", "/ui/certificates/rotate"} {
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
	// Logging in again from a browser that still holds a session drops the
	// old session: its token no longer works.
	c3 := e.login("bob")
	old := c3.cookies[e.h.sessionCookieName()]
	code(t, c3.act("/ui/login", url.Values{"username": {"bob"}, "password": {"bob-pw"}}), 303)
	if c3.cookies[e.h.sessionCookieName()] == old {
		t.Fatal("login kept the old session token")
	}
	stale := e.client()
	stale.cookies[e.h.sessionCookieName()] = old
	code(t, stale.get("/ui/grants"), 303)
	code(t, c3.get("/ui/grants"), 200)
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
	r := bob.act("/ui/grants", url.Values{"prefix": {"10.1.3.1"}, "wildcard": {"true"}})
	code(t, r, 403)
	see(t, r, "may not allow wildcard certificates")
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

	// Wildcard allowed for wildcard_allowed and admin; an admin's CIDR is
	// masked.
	code(t, carol.act("/ui/grants", url.Values{"prefix": {"10.9.9.9"}, "wildcard": {"true"}}), 303)
	code(t, admin.act("/ui/grants", url.Values{"prefix": {"10.8.0.1/16"}, "wildcard": {"true"}}), 303)
	cg, _ := e.store.Grants().List(bg, e.userID("carol"))
	if len(cg) != 1 || cg[0].Prefix.String() != "10.9.9.9/32" || !cg[0].Wildcard {
		t.Fatalf("carol: %+v", cg)
	}
	if ag, _ := e.store.Grants().List(bg, e.userID("alice")); len(ag) != 1 || ag[0].Prefix.String() != "10.8.0.0/16" {
		t.Fatalf("alice: %+v", ag)
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
	// Everyone sees every grant with its owner, but changes only their own:
	// someone else's grant answers 403 and stays as it is.
	page = bob.get("/ui/grants")
	see(t, page, "10.9.9.9/32", "carol", "10.8.0.0/16", "alice", "10.1.2.3/32")
	if strings.Count(page.body, `action="/ui/grants/`) != 2 {
		t.Errorf("bob gets action forms for grants he does not own:\n%s", trim(page.body))
	}
	for _, a := range []string{"disable", "enable", "delete"} {
		code(t, bob.act("/ui/grants/"+itoa(cg[0].ID)+"/"+a, nil), 403)
	}
	if g, err := e.store.Grants().Get(bg, cg[0].ID); err != nil || !g.Enabled {
		t.Errorf("carol's grant changed by bob: %+v %v", g, err)
	}
	code(t, bob.act(path+"/explode", nil), 404)
	code(t, bob.act("/ui/grants/9999/delete", nil), 404)
	r = bob.act(path+"/delete", url.Values{"owner": {"mine"}})
	code(t, r, 303)
	if loc := r.hdr.Get("Location"); loc != "/ui/grants?owner=mine" {
		t.Errorf("redirect keeps the filter: %q", loc)
	}
	if _, err := e.store.Grants().Get(bg, id); !isNotFound(err) {
		t.Errorf("not deleted: %v", err)
	}
	// The owner filter: everyone, mine, one owner.
	code(t, bob.act("/ui/grants", url.Values{"prefix": {"10.1.2.4"}}), 303)
	mine := bob.get("/ui/grants?owner=mine")
	see(t, mine, "10.1.2.4/32")
	lacks(t, mine, "10.9.9.9/32", "10.8.0.0/16")
	byCarol := bob.get("/ui/grants?owner=carol")
	see(t, byCarol, "10.9.9.9/32")
	lacks(t, byCarol, "10.1.2.4/32", "10.8.0.0/16")
	see(t, bob.get("/ui/grants?owner=all"), "10.9.9.9/32", "10.1.2.4/32", "10.8.0.0/16")
	// An admin manages everyone's grants on the same page.
	code(t, admin.act("/ui/grants/"+itoa(cg[0].ID)+"/disable", nil), 303)
	if g, _ := e.store.Grants().Get(bg, cg[0].ID); g.Enabled {
		t.Error("admin disable failed")
	}
	code(t, admin.act("/ui/grants/"+itoa(cg[0].ID)+"/delete", nil), 303)
	if _, err := e.store.Grants().Get(bg, cg[0].ID); !isNotFound(err) {
		t.Errorf("admin delete failed: %v", err)
	}
	// The old admin page is gone.
	code(t, admin.get("/ui/admin/grants"), 404)

	// Audit: grant changes are recorded and part of everyone's activity log.
	evs, _ := e.audit.Query(bg, core.AuditQuery{Type: core.AuditGrantChange})
	if len(evs) < 5 {
		t.Errorf("grant audit events: %d", len(evs))
	}
	see(t, bob.get("/ui/audit"), "Added address 10.9.9.9/32 (wildcards allowed).", "Deleted address 10.1.2.3/32.", "Disabled address 10.9.9.9/32.", "carol")
}

// TestRangeGrantsAdminOnly: users who are not admins add single addresses
// only; an address range is an admin's call. Their existing wider grants stay
// in force and they may still disable or delete them, but not re-enable them.
func TestRangeGrantsAdminOnly(t *testing.T) {
	e := newEnv(t)
	admin := e.login("alice")
	ap := admin.get("/ui/grants")
	see(t, ap, "Add address</h2>", "IPv4 address or range <input", `placeholder="10.1.2.3, 10.1.2.4 or 10.1.2.0/24"`, "range such as /24 or /16", ">Add address</button>")
	lacks(t, ap, "network", "Network", `href="#add"`)
	for i, role := range []core.Role{core.RoleNormal, core.RoleWildcardAllowed} {
		user := []string{"bob", "carol"}[i]
		c := e.loginAs(user, role)
		uid := e.userID(user)
		net := "10.5." + itoa(int64(i)) + "."

		page := c.get("/ui/grants")
		see(t, page, "Add address</h2>", "IPv4 address <input", `placeholder="10.1.2.3, 10.1.2.4 or 10.1.2.3/32"`, "Separate several with commas or spaces.", "<th>Address</th>", ">Add address</button>")
		lacks(t, page, "IPv4 address or range", "10.1.2.0/24", "range", "network", "Network", `href="#add"`)

		code(t, c.act("/ui/grants", url.Values{"prefix": {net + "1"}}), 303)
		code(t, c.act("/ui/grants", url.Values{"prefix": {net + "2/32"}}), 303)
		for _, wide := range []string{net + "0/24", net + "2/31", "10.0.0.0/8"} {
			r := c.act("/ui/grants", url.Values{"prefix": {wide}, "note": {"lab"}})
			code(t, r, 403)
			see(t, r, "Only administrators can add an address range. Add a single address (10.1.2.3 or 10.1.2.3/32).", `value="`+wide+`"`)
		}
		gs, _ := e.store.Grants().List(bg, uid)
		if len(gs) != 2 || gs[0].Prefix.Bits() != 32 || gs[1].Prefix.Bits() != 32 {
			t.Fatalf("%s: %+v", role, gs)
		}

		// A wider grant they own from before the rule: it stays in force,
		// they may disable and delete it, but only an admin re-enables it.
		old := &core.Grant{OwnerUserID: uid, Prefix: netip.MustParsePrefix(net + "0/24"), Enabled: true, CreatedAt: e.clock.Now()}
		if err := e.store.Grants().Create(bg, old); err != nil {
			t.Fatal(err)
		}
		path := "/ui/grants/" + itoa(old.ID)
		see(t, c.get("/ui/grants"), `action="`+path+`/disable"`)
		code(t, c.act(path+"/disable", nil), 303)
		page = c.get("/ui/grants")
		see(t, page, net+"0/24", `action="`+path+`/delete"`)
		lacks(t, page, `action="`+path+`/enable"`)
		r := c.act(path+"/enable", nil)
		code(t, r, 403)
		see(t, r, "Only administrators can enable an address range.")
		if g, _ := e.store.Grants().Get(bg, old.ID); g.Enabled {
			t.Fatalf("%s re-enabled an address range", role)
		}
		see(t, admin.get("/ui/grants"), `action="`+path+`/enable"`)
		code(t, admin.act(path+"/enable", nil), 303)
		if g, _ := e.store.Grants().Get(bg, old.ID); !g.Enabled {
			t.Fatal("admin could not enable the range")
		}
		code(t, c.act(path+"/delete", nil), 303)
		if _, err := e.store.Grants().Get(bg, old.ID); !isNotFound(err) {
			t.Fatalf("%s could not delete their range: %v", role, err)
		}
	}
	// Admins add ranges from /8 to /32; anything wider is refused for
	// everyone with 400.
	want := []string{"10.0.0.0/8", "10.6.0.0/16", "10.7.0.0/23", "10.6.0.0/24"}
	for _, p := range []string{"10.0.0.0/8", "10.6.1.2/16", "10.7.1.0/23", "10.6.0.0/24"} {
		code(t, admin.act("/ui/grants", url.Values{"prefix": {p}}), 303)
	}
	ag, _ := e.store.Grants().List(bg, e.userID("alice"))
	var got []string
	for _, g := range ag {
		got = append(got, g.Prefix.String())
	}
	slices.Sort(got)
	slices.Sort(want)
	if !slices.Equal(got, want) {
		t.Fatalf("admin ranges: %v, want %v", got, want)
	}
	for _, c := range []*client{admin, e.login("bob")} {
		for _, p := range []string{"8.0.0.0/7", "0.0.0.0/0", "10.0.0.0/1"} {
			r := c.act("/ui/grants", url.Values{"prefix": {p}})
			code(t, r, 400)
			see(t, r, "A range wider than /8 is refused.")
		}
	}
	if ag, _ := e.store.Grants().List(bg, e.userID("alice")); len(ag) != len(want) {
		t.Fatalf("a refused range was stored: %+v", ag)
	}
}

// TestGrantMultipleEntries: the Add address field takes several entries
// separated by commas and whitespace, all checked with the caller's rules
// before anything is stored.
func TestGrantMultipleEntries(t *testing.T) {
	e := newEnv(t)
	bob := e.login("bob")
	admin := e.login("alice")
	bid := e.userID("bob")
	prefixes := func(uid int64) []string {
		gs, _ := e.store.Grants().List(bg, uid)
		var out []string
		for _, g := range gs {
			out = append(out, g.Prefix.String())
		}
		slices.Sort(out)
		return out
	}

	// One bad entry stores nothing; the form names every refused entry and
	// keeps the typed text.
	in := "10.1.2.3, 10.1.2.0/24 nonsense 10.1.2.4"
	r := bob.act("/ui/grants", url.Values{"prefix": {in}})
	code(t, r, 400)
	see(t, r, "Nothing was added: 2 of 4 entries were refused.",
		"<code>10.1.2.0/24</code>: Only administrators can add an address range.",
		"<code>nonsense</code>: Not a valid IPv4 address.", `value="`+in+`"`)
	lacks(t, r, "<code>10.1.2.3</code>")
	r = bob.act("/ui/grants", url.Values{"prefix": {"10.1.2.3 10.1.2.0/24"}})
	code(t, r, 403)
	see(t, r, "Nothing was added: 1 of 2 entries were refused.")
	if got := prefixes(bid); len(got) != 0 {
		t.Fatalf("refused input stored grants: %v", got)
	}

	// Mixed separators, duplicates collapse (10.1.2.3 and 10.1.2.3/32 are
	// one), the note and wildcard apply to each, one audit event per grant.
	carol := e.loginAs("carol", core.RoleWildcardAllowed)
	r = carol.act("/ui/grants", url.Values{"prefix": {"10.1.2.3, 10.1.2.4\n10.1.2.5/32,,10.1.2.3/32\t10.1.2.3"}, "note": {"rack 4"}, "wildcard": {"true"}})
	code(t, r, 303)
	see(t, carol.get("/ui/grants"), "Added 3 addresses: 10.1.2.3/32, 10.1.2.4/32, 10.1.2.5/32.")
	cid := e.userID("carol")
	if got := prefixes(cid); !slices.Equal(got, []string{"10.1.2.3/32", "10.1.2.4/32", "10.1.2.5/32"}) {
		t.Fatalf("carol: %v", got)
	}
	gs, _ := e.store.Grants().List(bg, cid)
	for _, g := range gs {
		if g.Note != "rack 4" || !g.Wildcard || !g.Enabled {
			t.Errorf("grant %+v", g)
		}
	}
	evs, _ := e.audit.Query(bg, core.AuditQuery{Type: core.AuditGrantChange})
	if len(evs) != 3 {
		t.Errorf("audit events: %d, want 3", len(evs))
	}

	// An address the user already owns is skipped and named; someone else's
	// same address does not count.
	code(t, carol.act("/ui/grants", url.Values{"prefix": {"10.1.2.4 10.1.2.6"}}), 303)
	see(t, carol.get("/ui/grants"), "Added address 10.1.2.6/32. Machines there can request certificates now. Already yours, skipped: 10.1.2.4/32.")
	code(t, carol.act("/ui/grants", url.Values{"prefix": {"10.1.2.4"}}), 303)
	see(t, carol.get("/ui/grants"), "Nothing was added. Already yours, skipped: 10.1.2.4/32.")
	code(t, bob.act("/ui/grants", url.Values{"prefix": {"10.1.2.4, 10.1.2.7/32"}}), 303)
	if got := prefixes(bid); !slices.Equal(got, []string{"10.1.2.4/32", "10.1.2.7/32"}) {
		t.Fatalf("bob: %v", got)
	}

	// Admins: each entry from /8 to /32; one too wide refuses all.
	r = admin.act("/ui/grants", url.Values{"prefix": {"10.20.0.0/16 10.21.0.0/7"}})
	code(t, r, 400)
	see(t, r, "<code>10.21.0.0/7</code>: A range wider than /8 is refused.")
	code(t, admin.act("/ui/grants", url.Values{"prefix": {"10.20.0.0/16, 10.30.1.0/24 10.40.0.9"}}), 303)
	if got := prefixes(e.userID("alice")); !slices.Equal(got, []string{"10.20.0.0/16", "10.30.1.0/24", "10.40.0.9/32"}) {
		t.Fatalf("alice: %v", got)
	}

	// The cap: at most 50 entries per submit; empty input is refused.
	var many []string
	for i := range 51 {
		many = append(many, "10.3.0."+itoa(int64(i+1)))
	}
	r = bob.act("/ui/grants", url.Values{"prefix": {strings.Join(many, " ")}})
	code(t, r, 400)
	see(t, r, "Enter at most 50 addresses at a time; this has 51.")
	code(t, bob.act("/ui/grants", url.Values{"prefix": {" , "}}), 400)
	code(t, bob.act("/ui/grants", url.Values{"prefix": {strings.Join(many[:50], ",")}}), 303)
	if got := prefixes(bid); len(got) != 52 {
		t.Fatalf("bob after 50: %d grants", len(got))
	}
	see(t, bob.get("/ui/grants"), "Added 50 addresses: 10.3.0.1/32, ", " and 40 more.")
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
	see(t, admin.follow(r), "Blocked bob.")
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
	r = bob.act("/ui/grants", url.Values{"prefix": {"10.0.1.1"}, "wildcard": {"true"}})
	code(t, r, 403)
	code(t, admin.act("/ui/admin/users/"+itoa(bid)+"/role", url.Values{"role": {"wildcard_allowed"}}), 303)
	code(t, bob.act("/ui/grants", url.Values{"prefix": {"10.0.1.1"}, "wildcard": {"true"}}), 303)
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

	evs, _ := e.audit.Query(bg, core.AuditQuery{Type: core.AuditUserChange})
	if len(evs) != 3 {
		t.Errorf("user_change events: %+v", evs)
	}
}

// TestActivityLog: users who are not admins see issuance activity and grant
// changes (successes, denials and failures alike) but never Detail, and no
// control-plane events; admins see everything.
func TestActivityLog(t *testing.T) {
	e := newEnv(t)
	na := e.clock.Now().Add(90 * 24 * time.Hour)
	for _, ev := range []core.AuditEvent{
		{Type: core.AuditIssue, Mode: core.ModeACME, Names: []string{"issued.example.com"}, Provider: "letsencrypt", Result: "ok", CertNotAfter: &na},
		{Type: core.AuditGate, Mode: core.ModeACME, SourceIP: "10.0.0.7", Names: []string{"denied.example.com"}, Decision: "deny", Reason: core.ReasonDNSMismatch, Result: "denied", Detail: "resolver https://doh.internal/x said 192.0.2.1"},
		{Type: core.AuditOrder, Mode: core.ModeDirect, Names: []string{"refused.example.com"}, Decision: "deny", Reason: core.ReasonRateLimited, Result: "denied", Detail: "budget key internal"},
		{Type: core.AuditIssue, Mode: core.ModeACME, Names: []string{"failed.example.com"}, Result: "failed", Detail: "upstream said acct/12345 boom"},
		{Type: core.AuditDNSPresent, Mode: core.ModeDNSProxy, Names: []string{"_acme-challenge.proxy.example.com"}, Decision: "allow", Result: "ok"},
		{Type: core.AuditLogin, Mode: core.ModeUI, SourceIP: "10.9.9.9", Username: "loginuser", Result: "failed", Detail: "ldap: invalid credentials"},
		{Type: core.AuditConfigChange, Mode: core.ModeUI, Username: "alice", Detail: "activated generation 7"},
		{Type: core.AuditProviderState, Provider: "letsencrypt", Detail: "circuit opened"},
		{Type: core.AuditDirectFetch, Mode: core.ModeDirect, Names: []string{"fetched.example.com"}, Result: "ok", Detail: "hit: generation 1"},
		{Type: core.AuditDNSCleanup, Mode: core.ModeDNSProxy, Names: []string{"_acme-challenge.cleaned.example.com"}, Result: "ok"},
		{Type: core.AuditError, Detail: "LDAP test failed: dial tcp"},
	} {
		e.audit.Record(bg, ev)
	}
	bob := e.login("bob")
	admin := e.login("alice")
	dave := e.login("dave")
	e.store.Users().SetBlocked(bg, e.userID("dave"), true)

	hidden := []string{"loginuser", "10.9.9.9", "activated generation", "circuit opened", "fetched.example.com", "cleaned.example.com", "LDAP test failed"}
	details := []string{"doh.internal", "budget key", "acct/12345", "invalid credentials", "hit: generation"}
	for _, c := range []*client{bob, dave} {
		r := c.get("/ui/audit")
		see(t, r, "issued.example.com", "Certificate issued by letsencrypt, valid until",
			"denied.example.com", "Request denied: a name does not resolve to the requesting address.",
			"refused.example.com", "Order refused: a certificate authority rate limit is reached.",
			"failed.example.com", "Issuance failed.", "proxy.example.com", "DNS-01 value published.")
		lacks(t, r, append(hidden, details...)...)
		// Neither a type filter nor a search reaches what is hidden.
		lacks(t, c.get("/ui/audit?type=login"), "loginuser")
		lacks(t, c.get("/ui/audit?type=config_change"), "activated generation")
		lacks(t, c.get("/ui/audit?q=doh.internal"), "denied.example.com")
		see(t, c.get("/ui/audit?q=DENIED.example"), "denied.example.com")
		see(t, c.get("/ui/audit?scope=all&q=loginuser"), "No events match.")
		lacks(t, c.get("/ui/"), "loginuser", "doh.internal")
	}
	r := admin.get("/ui/audit")
	see(t, r, "issued.example.com", "denied.example.com")
	see(t, r, append(hidden, details...)...)
	see(t, admin.get("/ui/audit?type=gate"), "denied.example.com")
	lacks(t, admin.get("/ui/audit?type=gate"), "issued.example.com")
	see(t, admin.get("/ui/audit?q=DOH.internal"), "denied.example.com")
	see(t, admin.get("/ui/audit?since=junk"), "invalid")
	// The status page lists outcomes only, for everyone.
	see(t, admin.get("/ui/"), "failed.example.com", "Issuance failed.")
	lacks(t, admin.get("/ui/"), "loginuser")
}

func TestAuditPaging(t *testing.T) {
	e := newEnv(t)
	for i := 0; i < 70; i++ {
		e.clock.Advance(time.Second)
		e.audit.Record(bg, core.AuditEvent{Type: core.AuditIssue, Names: []string{"n" + fmtI(int64(i)) + ".example.com"}})
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
	see(t, r, "Needs attention", "CA accounts for CAA", "DNS zones and CAA", account, "example.com", "wide open zone", "is unprotected", "accounturi=", "LDAP is not configured", "unavailable", "retry in 1h00m", "too many")
	see(t, r, "1 valid ACME certificates; 1 direct entries (1 valid)", "is rate_limited until")
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
	see(t, r, `<span class="pill ok">operational</span>`)
	lacks(t, r, "unavailable", "is healthy until")
	see(t, admin.get("/ui/admin/providers"), `<span class="pill ok">healthy</span>`)
	lacks(t, admin.get("/ui/admin/providers"), "circuit open")

	bob := e.login("bob")
	r = bob.get("/ui/")
	lacks(t, r, account, "unprotected", "DNS zones and CAA", "Needs attention", "valid ACME certificates")
	see(t, r, "letsencrypt", "operational", "www.example.com")

	// LDAP not checked yet: no warning. A failed "Test LDAP" shows one, a
	// passing one clears it.
	e.cfg.Activate(bg, []byte(ldapGoodYAML))
	lacks(t, admin.get("/ui/"), "LDAP check", "LDAP is not configured")
	e.ldap.set(errLDAPDown)
	r = admin.act("/ui/admin/config/test-ldap", nil)
	see(t, admin.follow(r), "LDAP test failed", "connection refused")
	see(t, admin.get("/ui/"), "The last LDAP check (Test LDAP, 2026-10-02 12:00:00 UTC) failed: dial tcp: connection refused")
	e.ldap.set(nil)
	see(t, admin.follow(admin.act("/ui/admin/config/test-ldap", nil)), "LDAP test succeeded")
	lacks(t, admin.get("/ui/"), "LDAP check")
	if evs, _ := e.audit.Query(bg, core.AuditQuery{Type: core.AuditError}); len(evs) != 1 {
		t.Errorf("error events: %d", len(evs))
	}
}

// TestStatusForUsers: users who are not admins get the simple status: one
// state per CA, the queue, rate-limit gauges by level, recent outcomes and
// what expires next, and none of the admin detail.
func TestStatusForUsers(t *testing.T) {
	e := newEnv(t)
	now := e.clock.Now()
	e.sched.SetSnapshot(core.SchedulerSnapshot{Providers: []core.ProviderSnapshot{{Name: "letsencrypt", Open: true, SlotsInUse: 1, SlotsTotal: 4, Waiting: 2,
		State: core.ProviderState{Name: "letsencrypt", Health: core.ProviderHealthy, LastError: "secret upstream text"},
		Budgets: []core.BudgetUsage{{Kind: core.BudgetNewOrder, Used: 150, Limit: 200, Window: 3 * time.Hour},
			{Kind: core.BudgetCertDomain, Key: "example.com", Used: 50, Limit: 50, Window: 7 * 24 * time.Hour},
			{Kind: core.BudgetCertDomain, Key: "quiet.example.com", Used: 1, Limit: 50, Window: 7 * 24 * time.Hour},
			{Kind: core.BudgetCertSet, Key: "www.example.com", Used: 1, Limit: 5, Window: 7 * 24 * time.Hour}}}}})
	seedCert(t, e, "c1", "www.example.com")
	seedCert(t, e, "c2", "api.example.com")
	e.audit.Record(bg, core.AuditEvent{Type: core.AuditIssue, Names: []string{"broken.example.com"}, Result: "failed", Detail: "upstream acct/99"})
	e.audit.Record(bg, core.AuditEvent{Type: core.AuditOrder, Names: []string{"admitted.example.com"}, Decision: "allow", Result: "ok"})

	bob := e.login("bob")
	r := bob.get("/ui/")
	code(t, r, 200)
	see(t, r, "letsencrypt", "operational", "<b>2</b><span>waiting for a slot", "<b>1 of 4</b><span>slots in use",
		"New orders", "150 of 200 used", "Caution", "Certificates for example.com", "50 of 50 used", "Exhausted", "Renewals of www.example.com", "1 of 5 used",
		`<div class="gauge caution">`, `<div class="gauge exhausted">`, `<div class="gauge ok">`, `width="75"`,
		"broken.example.com", "Issuance failed.", "www.example.com", "api.example.com", "Expiring next")
	lacks(t, r, "quiet.example.com", "admitted.example.com", "upstream acct/99", "secret upstream text", "Needs attention", "DNS zones and CAA", "CA accounts for CAA")

	// A provider that answered with errors is degraded; one whose circuit is
	// open is unavailable with its retry time.
	e.sched.SetSnapshot(core.SchedulerSnapshot{Providers: []core.ProviderSnapshot{{Name: "letsencrypt", Open: true,
		State: core.ProviderState{Name: "letsencrypt", Health: core.ProviderHealthy, Failures: 2}}}})
	see(t, bob.get("/ui/"), "degraded")
	e.sched.SetSnapshot(core.SchedulerSnapshot{Providers: []core.ProviderSnapshot{{Name: "letsencrypt", Open: false,
		State: core.ProviderState{Name: "letsencrypt", Health: core.ProviderUnavailable, RetryAfter: now.Add(time.Hour)}}}})
	see(t, bob.get("/ui/"), "unavailable", "retry in 1h00m")
}

func TestLifetime(t *testing.T) {
	nb := coretest.At(2026, 1, 1, 0)
	na := nb.Add(90 * 24 * time.Hour)
	l := newLifetime(nb.Add(30*24*time.Hour), nb, na, time.Time{})
	if l.NowPct != 33 || l.RenewPct != 66 || !l.RenewExpected || l.State != "ok" {
		t.Errorf("ok: %+v", l)
	}
	l = newLifetime(nb.Add(80*24*time.Hour), nb, na, nb.Add(70*24*time.Hour))
	if l.NowPct != 88 || l.RenewPct != 77 || l.RenewExpected || l.State != "due" {
		t.Errorf("due: %+v", l)
	}
	if l = newLifetime(na.Add(time.Hour), nb, na, time.Time{}); l.State != "expired" || l.NowPct != 100 {
		t.Errorf("expired: %+v", l)
	}
}

// zonesStub is a fixed ZoneStatusSource.
type zonesStub []ZoneStatus

func (z zonesStub) ZoneStatuses() []ZoneStatus { return z }

func seedCert(t *testing.T, e *env, id, name string) { seedGrantCert(t, e, id, name, 0) }

// seedGrantCert issues a certificate whose order was authorized by grantID
// (0: by DNS match) from 10.0.0.5.
func seedGrantCert(t *testing.T, e *env, id, name string, grantID int64) {
	t.Helper()
	now := e.clock.Now()
	o := &core.Order{ID: "o-" + id, Mode: core.ModeACME, AccountID: "acct1", Names: names.MustSet(name), SourceIP: mustAddr("10.0.0.5"), GrantID: grantID, Status: core.OrderReady, Prep: core.PrepIntent,
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
	bob := e.login("bob")
	carol := e.login("carol")
	code(t, carol.act("/ui/grants", url.Values{"prefix": {"10.0.0.5"}}), 303)
	code(t, bob.act("/ui/grants", url.Values{"prefix": {"10.9.0.1"}}), 303)
	cg, _ := e.store.Grants().List(bg, e.userID("carol"))
	bgr, _ := e.store.Grants().List(bg, e.userID("bob"))
	seedGrantCert(t, e, "c3", "carols.example.com", cg[0].ID)
	seedGrantCert(t, e, "c4", "gone.example.com", bgr[0].ID)
	seedGrantCert(t, e, "c5", "c5.example.com", cg[0].ID) // the direct entry's certificate
	code(t, bob.act("/ui/grants/"+itoa(bgr[0].ID)+"/delete", nil), 303)
	e.store.Direct().Put(bg, &core.DirectEntry{Identifier: "svc.example.com", Generation: 2, CertificateID: "c5", Provider: "letsencrypt", NotBefore: now.Add(-time.Hour), NotAfter: now.Add(30 * 24 * time.Hour),
		RenewAt: now.Add(20 * 24 * time.Hour), LastFetchAt: now, LastFetchIP: mustAddr("10.2.2.2"), CreatedAt: now, UpdatedAt: now, LastError: "boom", Failures: 2})
	r := bob.get("/ui/certificates")
	see(t, r, "www.example.com", "api.example.com", "svc.example.com", "10.2.2.2", "renewal failing")
	lacks(t, r, "Rotate key", "boom")
	// Owners: the grant's owner and address, a deleted grant with the
	// requesting address, or no owner for a DNS match.
	see(t, r, `carol<span class="cell-sub">via <code>10.0.0.5/32</code>`, `address removed</span><span class="cell-sub">requested from <code>10.0.0.5</code>`, `no owner</span><span class="cell-sub">DNS match from <code>10.0.0.5</code>`)
	if n := strings.Count(r.body, "via <code>10.0.0.5/32</code>"); n != 3 { // c3, c5 and the direct entry
		t.Errorf("carol owns %d rows, want 3", n)
	}
	lacks(t, bob.get("/ui/certificates?q=api"), "www.example.com", "svc.example.com")
	see(t, bob.get("/ui/certificates?q=API"), "api.example.com")
	lacks(t, bob.get("/ui/certificates?mode=direct"), "www.example.com")
	lacks(t, bob.get("/ui/certificates?mode=acme"), "svc.example.com")
	lacks(t, bob.get("/ui/certificates?provider=other"), "www.example.com", "svc.example.com")

	admin := e.login("alice")
	see(t, admin.get("/ui/certificates"), "Rotate key", "boom")
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
	see(t, r, "active", "Roll back")
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

	evs, _ := e.audit.Query(bg, core.AuditQuery{Type: core.AuditConfigChange})
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
	evs, _ := e.audit.Query(bg, core.AuditQuery{Contains: "secret"})
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
		State: core.ProviderState{Name: "letsencrypt", Health: core.ProviderUnavailable, RetryAfter: e.clock.Now().Add(10 * time.Minute), Failures: 3, LastError: "503 upstream"},
		Budgets: []core.BudgetUsage{{Kind: core.BudgetNewOrder, Used: 150, Limit: 200, Window: 3 * time.Hour},
			{Kind: core.BudgetCertSet, Key: "www.example.com", Used: 4, Limit: 4, RenewalOnly: 1, Window: 7 * 24 * time.Hour}}}}})
	admin := e.login("alice")
	r := admin.get("/ui/admin/providers")
	account, _ := e.ca.AccountURL(bg)
	see(t, r, "letsencrypt", "503 upstream", "150 of 200 used", "10m", account, "https://acme.example/dir", "circuit open", ">Budgets</h3>")
	lacks(t, r, "Reset")

	// A used-up budget is marked exhausted and drawn full; a budget with
	// room is at caution from 75 % used, ok below.
	exhausted := `<div class="gauge exhausted"><div class="gauge-head"><span class="label">Renewals of www.example.com</span><span class="num">4 of 4 used</span>`
	see(t, r, exhausted, `width="100" height="8" rx="1"/></svg>`, "1 kept for renewals", `<div class="gauge caution"><div class="gauge-head"><span class="label">New orders</span><span class="num">150 of 200 used</span>`)
	if n := strings.Count(r.body, `<div class="gauge exhausted">`); n != 1 {
		t.Errorf("exhausted gauges: %d", n)
	}
	// The status page shows every budget to an admin.
	see(t, admin.get("/ui/"), exhausted)
}

func TestBanners(t *testing.T) {
	e := newEnv(t, envOpts{banners: []string{"DNS gate is mocked: <dev>"}})
	// Shown before login and on every page after it, escaped.
	see(t, e.client().get("/ui/login"), "DNS gate is mocked: &lt;dev&gt;")
	bob := e.login("bob")
	see(t, bob.get("/ui/"), "DNS gate is mocked")
	see(t, bob.get("/ui/grants"), "DNS gate is mocked")
	// A persistent banner is a status region, not an alert that interrupts
	// screen-reader users on every page.
	r := bob.get("/ui/")
	see(t, r, `class="notice error banner" role="status"`)
	lacks(t, r, `role="alert"`)

	lacks(t, newEnv(t).client().get("/ui/login"), "DNS gate is mocked")
}

func TestNotFoundPageAndFavicon(t *testing.T) {
	e := newEnv(t)
	c := e.client()
	// An unknown path under /ui/ renders the styled page, logged in or not.
	r := c.get("/ui/no-such-page")
	code(t, r, 404)
	if ct := r.hdr.Get("Content-Type"); !strings.HasPrefix(ct, "text/html") {
		t.Errorf("content type %q", ct)
	}
	see(t, r, "<title>Page not found – TLS broker</title>", `class="brand"`, "There is nothing here", `href="/ui/static/ui.css?v=`)
	lacks(t, r, `href="/ui/grants"`)
	bob := e.login("bob")
	r = bob.get("/ui/admin/nope/")
	code(t, r, 404)
	see(t, r, "There is nothing here", `href="/ui/grants"`, "Log out")
	// The exact routes still win over the catch-all, and a wrong method on
	// a known path stays a 405.
	code(t, bob.get("/ui/"), 200)
	code(t, bob.get("/ui/grants"), 200)
	code(t, bob.get("/ui/logout"), 405)

	// Every page links the favicon with the asset hash; the file is served
	// as SVG with the same long cache as the other static assets.
	see(t, r, `<link rel="icon" type="image/svg+xml" href="/ui/static/favicon.svg?v=`+e.h.assets+`">`)
	r = c.get("/ui/static/favicon.svg?v=" + e.h.assets)
	code(t, r, 200)
	if ct := r.hdr.Get("Content-Type"); !strings.HasPrefix(ct, "image/svg+xml") {
		t.Errorf("favicon content type %q", ct)
	}
	if cc := r.hdr.Get("Cache-Control"); !strings.Contains(cc, "immutable") {
		t.Errorf("favicon Cache-Control %q", cc)
	}
	see(t, r, "<svg")
}

// TestAssets: the self-hosted fonts are served under the CSP's font-src, the
// theme script runs before the stylesheet (no flash of the wrong theme), and
// no page uses an inline style or script, which the CSP would block.
func TestAssets(t *testing.T) {
	e := newEnv(t, envOpts{rotator: &rotatorStub{}})
	c := e.client()
	for _, f := range []string{"IBMPlexSans-Regular-Latin1.woff2", "IBMPlexSans-Medium-Latin1.woff2", "IBMPlexSans-SemiBold-Latin1.woff2", "IBMPlexMono-Regular-Latin1.woff2", "OFL.txt"} {
		r := c.get("/ui/static/fonts/" + f)
		code(t, r, 200)
		if strings.HasSuffix(f, ".woff2") && r.hdr.Get("Content-Type") != "font/woff2" {
			t.Errorf("%s: content type %q", f, r.hdr.Get("Content-Type"))
		}
	}
	see(t, c.get("/ui/static/ui.css"), `url("fonts/IBMPlexSans-Regular-Latin1.woff2")`, `:root[data-theme="dark"]`, `:root:not([data-theme="light"])`)
	see(t, c.get("/ui/static/theme.js"), "localStorage", "data-theme")
	seedCert(t, e, "c1", "www.example.com")
	admin := e.login("alice")
	for _, p := range append(allPages, pageSpec{path: "/ui/login"}, pageSpec{path: "/ui/nope"}) {
		r := admin.get(p.path)
		if p.path == "/ui/login" {
			r = c.get(p.path)
		}
		head := r.body[:strings.Index(r.body, "</head>")]
		th, css := strings.Index(head, `<script src="/ui/static/theme.js?v=`), strings.Index(head, `<link rel="stylesheet"`)
		if th < 0 || css < 0 || th > css || strings.Contains(head[th:css], "defer") {
			t.Errorf("%s: theme script must load, undeferred, before the stylesheet", p.path)
		}
		lacks(t, r, ` style="`, "<style", "<script>", "onclick=", " - TLS broker", " · ")
	}
}

func TestFormBodyLimits(t *testing.T) {
	e := newEnv(t)
	admin := e.login("alice")
	tok := admin.csrf()
	big := strings.Repeat("a", 2<<20)
	// With the token in the header the CSRF middleware never reads the
	// body, so the handler's own limit is the only one.
	post := func(path string, form url.Values) resp {
		req, _ := http.NewRequest("POST", e.srv.URL+path, strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set(auth.CSRFHeader, tok)
		return admin.send(req)
	}
	code(t, post("/ui/admin/config/validate", url.Values{"yaml": {big}}), 413)
	code(t, post("/ui/admin/config/activate", url.Values{"yaml": {big}}), 413)
	code(t, post("/ui/admin/config/rollback", url.Values{"gen": {big}}), 413)
	code(t, post("/ui/admin/secrets", url.Values{"name": {"k"}, "value": {big}}), 413)
	code(t, post("/ui/admin/secrets/delete", url.Values{"name": {big}}), 413)
	code(t, post(fmt.Sprintf("/ui/admin/users/%d/role", e.userID("alice")), url.Values{"role": {big}}), 413)
	// A token in the form field: the middleware's 1 MiB cap refuses it first.
	code(t, admin.post("/ui/admin/config/validate", url.Values{"yaml": {big}, "csrf_token": {tok}}), 403)
	// Nothing was stored, and ordinary posts still work.
	if n, _ := e.secrets.List(bg); len(n) != 0 {
		t.Errorf("secrets written: %v", n)
	}
	if e.cfg.Current().Generation != 2 {
		t.Errorf("generation %d", e.cfg.Current().Generation)
	}
	code(t, post("/ui/admin/config/validate", url.Values{"yaml": {goodYAML}}), 200)
}

// The zones section: a zone whose CAA pins wildcards to the broker's and
// other accounts is protected and says the broker's account is among them;
// one that pins other accounts only is protected too, but warns that the
// broker cannot issue its wildcards. A leftover trusted_accounts key in the
// active generation is ignored with a warning. The suggested records keep
// ordinary names open to every CA (unpinned issue) and pin issuewild to the
// broker's account, with a reminder for the operator's own accounts.
func TestDashboardZonesCAA(t *testing.T) {
	e := newEnv(t)
	y := strings.Replace(goodYAML, "    hosted_zone_id: Z0123456789ABC\n",
		"    hosted_zone_id: Z0123456789ABC\n    trusted_accounts:\n      - https://acme.example/acme/acct/77\n", 1)
	if _, chk, err := e.cfg.Activate(bg, []byte(y)); err != nil || !chk.OK() {
		t.Fatalf("activate: %v %+v", err, chk)
	}
	e.caa.m["example.com"] = core.CAAStatus{Name: "example.com", Node: "example.com", WildcardProtected: true,
		BrokerWildcard: core.BrokerPinned,
		Detail:         "CAA issuewild at example.com allows *.example.com only to 2 pinned accounts at letsencrypt.org; the broker's account at letsencrypt.org is among them"}
	account, _ := e.ca.AccountURL(bg)
	r := e.login("alice").get("/ui/")
	see(t, r, "broker's account pinned", "only to 2 pinned accounts at letsencrypt.org; the broker&#39;s account at letsencrypt.org is among them",
		"zones[0].trusted_accounts: is no longer used and is ignored",
		`example.com. CAA 0 issue &#34;letsencrypt.org&#34;`,
		`example.com. CAA 0 issuewild &#34;letsencrypt.org; accounturi=`+account+`&#34;`,
		"for each ACME account of yours that needs wildcards")
	lacks(t, r, `CAA 0 issue &#34;letsencrypt.org; accounturi`, "is unprotected", "trusted operator account", "cannot issue *.example.com")

	e.caa.m["example.com"] = core.CAAStatus{Name: "example.com", Node: "example.com", WildcardProtected: true,
		BrokerWildcard: core.BrokerNotPinned,
		Detail:         "CAA issuewild at example.com allows *.example.com only to 1 pinned account at letsencrypt.org; the broker's own account is not among them, so the broker cannot obtain *.example.com itself"}
	r = e.login("alice").get("/ui/")
	see(t, r, "broker's account not pinned", "the broker itself cannot issue *.example.com (ACME proxy, direct API)")
	lacks(t, r, "is unprotected")
}

// Suggested records follow architecture §9: unpinned issue for every CA,
// issuewild only for the broker's account at the most preferred provider
// that honours accounturi (not one per provider), and a reminder for the
// operator's own accounts.
func TestSuggestCAA(t *testing.T) {
	le := accountView{Provider: "letsencrypt", URL: "https://acme-v02.api.letsencrypt.org/acme/acct/1", Honoured: true, Issuers: []string{"letsencrypt.org"}}
	goog := accountView{Provider: "google", URL: "https://dv.acme-v02.api.pki.goog/account/x", Honoured: false, Issuers: []string{"pki.goog"}}
	goog2 := goog
	goog2.Honoured = true
	want := []string{
		`example.com. CAA 0 issue "letsencrypt.org"`,
		`example.com. CAA 0 issue "pki.goog"`,
		`example.com. CAA 0 issuewild "letsencrypt.org; accounturi=https://acme-v02.api.letsencrypt.org/acme/acct/1"`,
		"; add one issuewild line like the above, with its own accounturi, for each ACME account of yours that needs wildcards",
	}
	for _, accts := range [][]accountView{{le, goog}, {le, goog2}} {
		if got := suggestCAA("example.com", accts); !slices.Equal(got, want) {
			t.Fatalf("%v:\n%q", accts, got)
		}
	}
	// The primary does not honour accounturi: the next one that does gets it.
	got := suggestCAA("example.com", []accountView{goog, {Provider: "le", URL: le.URL, Honoured: true, Issuers: le.Issuers}})
	if len(got) != 4 || got[2] != want[2] {
		t.Fatalf("%q", got)
	}
	// None honours it, or none has an account URL yet.
	if got := suggestCAA("example.com", []accountView{goog}); len(got) != 2 || !strings.Contains(got[1], "wildcards cannot be pinned") {
		t.Fatalf("%q", got)
	}
	if got := suggestCAA("example.com", []accountView{{Provider: "le", Err: "down", Honoured: true, Issuers: le.Issuers}}); got != nil {
		t.Fatalf("%q", got)
	}
}

const ldapGoodYAML = goodYAML + "ldap:\n  url: ldaps://ldap.example.com:636\n  base_dn: dc=example,dc=com\n  user_filter: (uid=%s)\n"

// The broker checks LDAP itself (CheckLDAP, run by the app at startup and
// on activation): the status page warns only after a failed check, with
// when and what triggered it, and a later passing check or a successful
// LDAP login clears it. The break-glass login is no evidence.
func TestLDAPCheck(t *testing.T) {
	e := newEnv(t)
	admin := e.login("alice")

	// Not configured: CheckLDAP does nothing; the existing warning stays.
	e.h.CheckLDAP(bg, "startup")
	if e.ldap.count() != 0 {
		t.Fatalf("tested without LDAP settings: %d", e.ldap.count())
	}
	see(t, admin.get("/ui/"), "LDAP is not configured")

	if _, chk, err := e.cfg.Activate(bg, []byte(ldapGoodYAML)); err != nil || !chk.OK() {
		t.Fatalf("activate: %v %+v", err, chk)
	}
	calls := e.ldap.count()

	// Success: no warning.
	e.h.CheckLDAP(bg, "startup")
	lacks(t, admin.get("/ui/"), "LDAP check", "LDAP is not configured", "has not been tested")

	// Failure: one warning with trigger, time and error.
	e.ldap.set(errLDAPDown)
	e.clock.Advance(time.Minute)
	e.h.CheckLDAP(bg, "generation 3")
	if e.ldap.count() != calls+2 {
		t.Fatalf("calls %d, want %d", e.ldap.count(), calls+2)
	}
	warn := "The last LDAP check (generation 3, 2026-10-02 12:01:00 UTC) failed: dial tcp: connection refused"
	see(t, admin.get("/ui/"), warn)

	// The break-glass admin logging in proves nothing about LDAP.
	e.login("root")
	see(t, admin.get("/ui/"), warn)
	// An LDAP user logging in does: the warning is gone, without a test.
	e.login("bob")
	lacks(t, admin.get("/ui/"), "LDAP check")
	if e.ldap.count() != calls+2 {
		t.Fatalf("login ran a test: %d", e.ldap.count())
	}

	// Failure again, then a passing check clears it.
	e.h.CheckLDAP(bg, "startup")
	see(t, admin.get("/ui/"), "The last LDAP check (startup")
	e.ldap.set(nil)
	e.h.CheckLDAP(bg, "startup")
	lacks(t, admin.get("/ui/"), "LDAP check")

	// A check cut short by shutdown records nothing.
	e.ldap.set(errLDAPDown)
	ctx, cancel := context.WithCancel(bg)
	cancel()
	e.h.CheckLDAP(ctx, "startup")
	lacks(t, admin.get("/ui/"), "LDAP check")
}
