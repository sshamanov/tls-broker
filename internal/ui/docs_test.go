package ui

import (
	"net/url"
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
	see(t, r, `<a href="/ui/docs" aria-current="page">Documentation</a>`, "<h1>TLS broker user guide</h1>",
		// The contents column lists the sections and their subsections.
		`<nav class="docs-nav" aria-labelledby="docs-nav-title"><div class="docs-group-title" id="docs-nav-title">Contents</div>`,
		`<li class="toc-l2"><a href="#getting-started">Getting started</a></li>`,
		`<li class="toc-l3"><a href="#getting-access">Getting access</a></li>`,
		`<li class="toc-l2"><a href="#acme-proxy-certbot-and-acmesh">ACME proxy: certbot and acme.sh</a></li>`,
		`<li class="toc-l3"><a href="#certbot-hooks">certbot hooks</a></li>`,
		`<li class="toc-l2"><a href="#api-reference">API reference</a></li>`,
		// One continuous text with every section.
		`<h2 id="getting-started">Getting started</h2>`, `<h3 id="certbot">certbot</h3>`,
		`<h2 id="troubleshooting">Troubleshooting</h2>`, `<h3 id="health-and-metrics">Health and metrics</h3>`,
		"--server http://10.9.8.7:8081/acme/directory",
		`<a href="#getting-access">Getting access</a>`,
		// A link to a reference page outside the guide is text with its path.
		`<span class="doc-repo">ACME proxy reference<span class="doc-repo-path"> (in the repository: <code>docs/acme-proxy.md</code>)</span></span>`)
	// The document's own contents list is the navigation, not repeated in
	// the text.
	lacks(t, r, "broker.example.com", `.md"`, "<script>", `id="contents"`, `href="/ui/docs/`)
	if strings.Count(r.body, `href="#getting-access"`) < 2 {
		t.Error("the contents and the text should both link to #getting-access")
	}
	if r.hdr.Get("Cache-Control") != "no-store" || !strings.Contains(r.hdr.Get("Content-Security-Policy"), "script-src 'self'") {
		t.Errorf("headers %v", r.hdr)
	}

	// The pages the guide used to be split into redirect to their section.
	for page, id := range map[string]string{
		"getting-started": "getting-started", "web-ui": "using-the-web-interface",
		"acme-proxy": "acme-proxy-certbot-and-acmesh", "dns-proxy": "dns-proxy-your-own-acme-account",
		"direct": "direct-download-curl-and-tar", "troubleshooting": "troubleshooting", "api": "api-reference",
	} {
		r := bob.get("/ui/docs/" + page)
		code(t, r, 301)
		if loc := r.hdr.Get("Location"); loc != "/ui/docs#"+id {
			t.Errorf("%s: location %q", page, loc)
		}
		see(t, bob.get("/ui/docs"), `<h2 id="`+id+`">`)
	}

	// Unknown names, the old index, the file name, traversal and nesting
	// are the 404 page.
	for _, p := range []string{"/ui/docs/", "/ui/docs/nope", "/ui/docs/README", "/ui/docs/guide", "/ui/docs/guide.md", "/ui/docs/api.md", "/ui/docs/..%2Fplan", "/ui/docs/%2E%2E", "/ui/docs/a/b", "/ui/docs/plan"} {
		r := bob.get(p)
		code(t, r, 404)
		see(t, r, "Page not found")
	}

	// Blocked users may read the documentation too.
	dave := e.login("dave")
	e.store.Users().SetBlocked(bg, e.userID("dave"), true)
	code(t, dave.get("/ui/docs/direct"), 301)
	see(t, dave.get("/ui/docs"), "Your account is blocked", `href="/ui/docs"`, `<h2 id="direct-download-curl-and-tar">`)
	// Anonymous: login first, for the old addresses too.
	for _, p := range []string{"/ui/docs", "/ui/docs/direct"} {
		r = e.client().get(p)
		code(t, r, 303)
		if !strings.HasPrefix(r.hdr.Get("Location"), "/ui/login?next="+url.QueryEscape(p)) {
			t.Errorf("%s: location %q", p, r.hdr.Get("Location"))
		}
	}
	// Admins too, and the nav item is there for everyone.
	see(t, e.loginAs("carol", core.RoleAdmin).get("/ui/"), `<a href="/ui/docs">Documentation</a>`)
}

func TestDocsNeverRenderHTML(t *testing.T) {
	e := newEnv(t, envOpts{docs: fstest.MapFS{
		"guide.md": {Data: []byte("# Guide\n\n<script>alert(1)</script>\n\nText <img src=x onerror=alert(1)> and [x](javascript:alert(1)).\n")},
	}})
	r := e.login("bob").get("/ui/docs")
	code(t, r, 200)
	see(t, r, "<h1>Guide</h1>")
	lacks(t, r, "<script>alert", "onerror", "javascript:")
}

func TestDocsUnavailable(t *testing.T) {
	e := newEnv(t, envOpts{noDocs: true})
	bob := e.login("bob")
	r := bob.get("/ui/docs")
	code(t, r, 200)
	see(t, r, "The documentation is not available in this build.", `<a href="/ui/docs" aria-current="page">Documentation</a>`, "docs/guide.md")
	// The old addresses still redirect; the reader then says so.
	code(t, bob.get("/ui/docs/acme-proxy"), 301)
}

func TestContextualDocsLinks(t *testing.T) {
	e := newEnv(t)
	bob := e.login("bob")
	see(t, bob.get("/ui/grants"), `<a href="/ui/docs#getting-access">How access works</a>`)
	see(t, bob.get("/ui/"), `<a href="/ui/docs#getting-started">How to get a certificate</a>`)
	// Both anchors are headings of the guide.
	see(t, bob.get("/ui/docs"), `<h3 id="getting-access">`, `<h2 id="getting-started">`)
}
