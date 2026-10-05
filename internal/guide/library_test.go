package guide

import (
	"errors"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"testing/fstest"
	"time"
)

var quiet = slog.New(slog.NewTextHandler(io.Discard, nil))

const testIndex = `# User guide

Read [the first page](first.md).

## Pages

- [First page](first.md)
- [Second page](second.md)
`

const testFirst = "# First page\n\n" +
	"Use `https://broker.example.com/acme/directory` or https://broker.example.com/cert/x.\n\n" +
	"## Links here\n\n" +
	"- [second](second.md#part-two) and [index](README.md) and [local](#links-here)\n" +
	"- [reference](../acme-proxy.md#errors) and [unlisted](unlisted.md) and [external](https://example.com/a)\n" +
	"- ![diagram](pic.png)\n\n" +
	"### Sub\n\n" +
	"```sh\ncurl https://broker.example.com/cert/www.example.com\n```\n\n" +
	"| a | b |\n|---|---|\n| 1 | 2 |\n"

func mapFS() fstest.MapFS {
	t0 := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	return fstest.MapFS{
		"README.md":   {Data: []byte(testIndex), ModTime: t0},
		"first.md":    {Data: []byte(testFirst), ModTime: t0},
		"second.md":   {Data: []byte("# Second page\n\n## Part two\n\nText.\n"), ModTime: t0},
		"unlisted.md": {Data: []byte("# Unlisted\n"), ModTime: t0},
	}
}

func TestLibraryRendersPages(t *testing.T) {
	l := New(mapFS(), quiet)
	x, err := l.Index()
	if err != nil {
		t.Fatal(err)
	}
	if x.Title != "User guide" || len(x.Groups) != 1 || x.Groups[0].Title != "Pages" || len(x.Names()) != 2 {
		t.Fatalf("index %+v", x)
	}
	p, err := l.Page("first", "https://tls.example.net:8443/")
	if err != nil {
		t.Fatal(err)
	}
	if p.Title != "First page" || strings.Contains(p.HTML, "<h1") {
		t.Errorf("title %q; the h1 belongs to the layout:\n%s", p.Title, p.HTML)
	}
	for _, want := range []string{
		`<h2 id="links-here">Links here</h2>`,
		`<h3 id="sub">Sub</h3>`,
		`<a href="/ui/docs/second#part-two">second</a>`,
		`<a href="/ui/docs">index</a>`,
		`<a href="#links-here">local</a>`,
		`<span class="doc-repo">reference<span class="doc-repo-path"> (in the repository: <code>docs/acme-proxy.md</code>)</span></span>`,
		`<span class="doc-repo">unlisted<span class="doc-repo-path"> (in the repository: <code>docs/guide/unlisted.md</code>)</span></span>`,
		`<a href="https://example.com/a">external</a>`,
		`<code>https://tls.example.net:8443/acme/directory</code>`,
		`<a href="https://tls.example.net:8443/cert/x">https://tls.example.net:8443/cert/x</a>`,
		`<pre><code class="language-sh">curl https://tls.example.net:8443/cert/www.example.com`,
		`<div class="doc-table"><table>`, `</table></div>`,
	} {
		if !strings.Contains(p.HTML, want) {
			t.Errorf("page lacks %s\n%s", want, p.HTML)
		}
	}
	for _, bad := range []string{"broker.example.com", ".md\"", "<img", "pic.png"} {
		if strings.Contains(p.HTML, bad) {
			t.Errorf("page contains %q\n%s", bad, p.HTML)
		}
	}
	if len(p.TOC) != 2 || p.TOC[0].ID != "links-here" || p.TOC[1].Level != 3 {
		t.Errorf("toc %+v", p.TOC)
	}
	// The index page itself.
	ip, err := l.Page("", "")
	if err != nil {
		t.Fatal(err)
	}
	if ip.Title != "User guide" || !strings.Contains(ip.HTML, `<a href="/ui/docs/first">the first page</a>`) {
		t.Errorf("index page %+v", ip)
	}
	// Without an external URL the placeholder stays; the cache keeps the
	// unsubstituted HTML.
	p2, _ := l.Page("first", "")
	if !strings.Contains(p2.HTML, "https://broker.example.com/acme/directory") {
		t.Error("placeholder replaced without an external URL")
	}
	// The substituted URL is escaped.
	p3, _ := l.Page("first", `https://h.example.com/"x&`)
	if !strings.Contains(p3.HTML, `https://h.example.com/&#34;x&amp;/acme/directory`) {
		t.Errorf("external URL not escaped:\n%s", p3.HTML)
	}
}

func TestLibraryNeverRendersHTML(t *testing.T) {
	fs := mapFS()
	fs["first.md"].Data = []byte("# First\n\n<script>alert(1)</script>\n\n<!-- note -->\n\n" +
		"Inline <b onclick=\"x()\">bold</b> and [js](javascript:alert(1)) and <img src=x onerror=y>.\n")
	p, err := New(fs, quiet).Page("first", "")
	if err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{"<script", "<b ", "onclick", "javascript:", "<img", "onerror"} {
		if strings.Contains(p.HTML, bad) {
			t.Errorf("raw HTML passed through (%s):\n%s", bad, p.HTML)
		}
	}
}

func TestLibraryServesOnlyListedPages(t *testing.T) {
	l := New(mapFS(), quiet)
	for _, name := range []string{"unlisted", "README", "readme", "../first", "first.md", "First", "/first", "sub/first", ".", "..", "-x"} {
		if _, err := l.Page(name, ""); !errors.Is(err, ErrNotFound) {
			t.Errorf("Page(%q) = %v, want ErrNotFound", name, err)
		}
	}
	// Listed but missing on disk.
	fs := mapFS()
	delete(fs, "second.md")
	if _, err := New(fs, quiet).Page("second", ""); !errors.Is(err, ErrNotFound) {
		t.Errorf("missing listed page: %v", err)
	}
}

func TestLibraryUnavailable(t *testing.T) {
	for name, l := range map[string]*Library{
		"nil":      New(nil, quiet),
		"empty":    New(fstest.MapFS{}, quiet),
		"missing":  New(os.DirFS(filepath.Join(t.TempDir(), "nope")), quiet),
		"no title": New(fstest.MapFS{"README.md": {Data: []byte("- [a](a.md)\n")}}, quiet),
	} {
		if _, err := l.Index(); !errors.Is(err, ErrUnavailable) {
			t.Errorf("%s: Index: %v", name, err)
		}
		if _, err := l.Page("first", ""); !errors.Is(err, ErrUnavailable) {
			t.Errorf("%s: Page: %v", name, err)
		}
	}
}

func TestLibraryCacheFollowsFiles(t *testing.T) {
	fs := mapFS()
	l := New(fs, quiet)
	if p, _ := l.Page("second", ""); !strings.Contains(p.HTML, "Text.") {
		t.Fatal(p.HTML)
	}
	// Same size and time: the cached rendering is used.
	fs["second.md"].Data = []byte("# Second page\n\n## Part two\n\nTEXT.\n")
	if p, _ := l.Page("second", ""); !strings.Contains(p.HTML, "Text.") {
		t.Error("re-rendered although the file looks unchanged")
	}
	// A new modification time renders it again.
	fs["second.md"].ModTime = fs["second.md"].ModTime.Add(time.Second)
	if p, _ := l.Page("second", ""); !strings.Contains(p.HTML, "TEXT.") {
		t.Error("changed file not rendered again")
	}
	// A new size too.
	fs["second.md"].Data = []byte("# Second page\n\nShorter.\n")
	if p, _ := l.Page("second", ""); !strings.Contains(p.HTML, "Shorter.") {
		t.Error("changed size not rendered again")
	}
	// A changed index changes what pages link to and what is served.
	fs["README.md"].Data = []byte("# User guide\n\n- [First page](first.md)\n- [Unlisted](unlisted.md)\n")
	if _, err := l.Page("unlisted", ""); err != nil {
		t.Errorf("newly listed page: %v", err)
	}
	if _, err := l.Page("second", ""); !errors.Is(err, ErrNotFound) {
		t.Errorf("unlisted page still served: %v", err)
	}
	if p, _ := l.Page("first", ""); !strings.Contains(p.HTML, `<span class="doc-repo">second`) {
		t.Errorf("link to a page no longer listed:\n%s", p.HTML)
	}
}

// TestRealGuideRenders renders every page of docs/guide the way the image
// serves it.
func TestRealGuideRenders(t *testing.T) {
	l := New(os.DirFS(filepath.Join(repoRoot, guideDir)), quiet)
	x, err := l.Index()
	if err != nil {
		t.Fatal(err)
	}
	href := regexp.MustCompile(`href="([^"]*)"`)
	for _, name := range append([]string{""}, x.Names()...) {
		p, err := l.Page(name, "http://192.0.2.10:8081")
		if err != nil {
			t.Fatalf("%q: %v", name, err)
		}
		if strings.Contains(p.HTML, Placeholder) || strings.Contains(p.HTML, "raw HTML omitted") {
			t.Errorf("%q: placeholder or raw HTML left", name)
		}
		for _, m := range href.FindAllStringSubmatch(p.HTML, -1) {
			h := m[1]
			if !strings.HasPrefix(h, "/ui/docs") && !strings.HasPrefix(h, "#") && !strings.HasPrefix(h, "https://") && !strings.HasPrefix(h, "http://192.0.2.10:8081") {
				t.Errorf("%q: link %q leads outside the reader", name, h)
			}
		}
	}
}
