package ui

import (
	"strings"
	"testing"
	"testing/fstest"

	"tls-broker/internal/core"
)

// activateURL makes ext the broker's server.external_url.
func (e *env) activateURL(ext string) {
	e.t.Helper()
	y := strings.Replace(goodYAML, "https://broker.example.com", ext, 1)
	if _, chk, err := e.cfg.Activate(bg, []byte(y)); err != nil || !chk.OK() {
		e.t.Fatalf("activate: %v %+v", err, chk)
	}
}

func TestDocsReader(t *testing.T) {
	e := newEnv(t)
	e.activateURL("http://10.9.8.7:8081")
	bob := e.login("bob")

	r := bob.get("/ui/docs")
	code(t, r, 200)
	see(t, r, `<a href="/ui/docs" aria-current="page">Documentation</a>`, "<h1>User guide</h1>",
		`<nav class="docs-nav" aria-label="Documentation">`, `<a href="/ui/docs/acme-proxy">ACME proxy: certbot and acme.sh</a>`,
		`<div class="docs-group-title">Getting certificates</div>`, `<a href="/ui/docs/getting-started">Getting started</a>`)
	if r.hdr.Get("Cache-Control") != "no-store" || !strings.Contains(r.hdr.Get("Content-Security-Policy"), "script-src 'self'") {
		t.Errorf("headers %v", r.hdr)
	}

	r = bob.get("/ui/docs/acme-proxy")
	code(t, r, 200)
	see(t, r, "<h1>ACME proxy: certbot and acme.sh</h1>",
		`<a href="/ui/docs/acme-proxy" aria-current="page">`,
		"--server http://10.9.8.7:8081/acme/directory",
		`<h2 id="certbot">certbot</h2>`, "On this page", `<a href="#certbot">certbot</a>`,
		`<a href="/ui/docs/getting-started#getting-access">Getting started</a>`,
		// A link to a reference page outside the guide is text with its path.
		`<span class="doc-repo">ACME proxy reference<span class="doc-repo-path"> (in the repository: <code>docs/acme-proxy.md</code>)</span></span>`)
	lacks(t, r, "broker.example.com", `.md"`, "<script>")

	// Unknown names, the index file, traversal and nesting are the 404 page.
	for _, p := range []string{"/ui/docs/", "/ui/docs/nope", "/ui/docs/README", "/ui/docs/api.md", "/ui/docs/..%2Fplan", "/ui/docs/%2E%2E", "/ui/docs/a/b", "/ui/docs/plan"} {
		r := bob.get(p)
		code(t, r, 404)
		see(t, r, "Page not found")
	}

	// Blocked users may read the documentation too.
	dave := e.login("dave")
	e.store.Users().SetBlocked(bg, e.userID("dave"), true)
	code(t, dave.get("/ui/docs/direct"), 200)
	see(t, dave.get("/ui/docs"), "Your account is blocked", `href="/ui/docs"`)
	// Anonymous: login first.
	r = e.client().get("/ui/docs/direct")
	code(t, r, 303)
	if !strings.HasPrefix(r.hdr.Get("Location"), "/ui/login?next=%2Fui%2Fdocs%2Fdirect") {
		t.Errorf("location %q", r.hdr.Get("Location"))
	}
	// Admins too, and the nav item is there for everyone.
	see(t, e.loginAs("carol", core.RoleAdmin).get("/ui/"), `<a href="/ui/docs">Documentation</a>`)
}

func TestDocsNeverRenderHTML(t *testing.T) {
	e := newEnv(t, envOpts{docs: fstest.MapFS{
		"README.md": {Data: []byte("# Guide\n\n- [Page](page.md)\n")},
		"page.md":   {Data: []byte("# Page\n\n<script>alert(1)</script>\n\nText <img src=x onerror=alert(1)> and [x](javascript:alert(1)).\n")},
	}})
	r := e.login("bob").get("/ui/docs/page")
	code(t, r, 200)
	lacks(t, r, "<script>alert", "onerror", "javascript:")
}

func TestDocsUnavailable(t *testing.T) {
	e := newEnv(t, envOpts{noDocs: true})
	bob := e.login("bob")
	r := bob.get("/ui/docs")
	code(t, r, 200)
	see(t, r, "The documentation is not available in this build.", `<a href="/ui/docs" aria-current="page">Documentation</a>`)
	r = bob.get("/ui/docs/acme-proxy")
	code(t, r, 200)
	see(t, r, "not available in this build")
}

func TestContextualDocsLinks(t *testing.T) {
	e := newEnv(t)
	bob := e.login("bob")
	see(t, bob.get("/ui/grants"), `<a href="/ui/docs/getting-started#getting-access">How access works</a>`)
	see(t, bob.get("/ui/"), `<a href="/ui/docs/getting-started">How to get a certificate</a>`)
}
