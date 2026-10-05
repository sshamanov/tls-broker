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

const testGuide = "# User guide\n\n" +
	"Intro with `https://broker.example.com/acme/directory` or https://broker.example.com/cert/x.\n\n" +
	"## Contents\n\n" +
	"- [Links here](#links-here)\n" +
	"  - [Sub](#sub)\n" +
	"- [Part two](#part-two)\n\n" +
	"## Links here\n\n" +
	"- [two](#part-two) and [local](#links-here)\n" +
	"- [reference](acme-proxy.md#errors) and [design](../architecture.md) and [external](https://example.com/a)\n" +
	"- ![diagram](pic.png)\n\n" +
	"### Sub\n\n" +
	"```sh\ncurl https://broker.example.com/cert/www.example.com\n```\n\n" +
	"| a | b |\n|---|---|\n| 1 | 2 |\n\n" +
	"## Part two\n\nText.\n\n#### Deep\n\nDeeper.\n"

func mapFS() fstest.MapFS {
	t0 := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	return fstest.MapFS{File: {Data: []byte(testGuide), ModTime: t0}}
}

func TestLibraryRendersTheGuide(t *testing.T) {
	l := New(mapFS(), quiet)
	p, err := l.Document("https://tls.example.net:8443/")
	if err != nil {
		t.Fatal(err)
	}
	if p.Title != "User guide" || strings.Contains(p.HTML, "<h1") {
		t.Errorf("title %q; the h1 belongs to the layout:\n%s", p.Title, p.HTML)
	}
	for _, want := range []string{
		`<h2 id="links-here">Links here</h2>`,
		`<h3 id="sub">Sub</h3>`,
		`<h4 id="deep">Deep</h4>`,
		`<a href="#part-two">two</a>`,
		`<a href="#links-here">local</a>`,
		`<span class="doc-repo">reference<span class="doc-repo-path"> (in the repository: <code>docs/acme-proxy.md</code>)</span></span>`,
		`<span class="doc-repo">design<span class="doc-repo-path"> (in the repository: <code>architecture.md</code>)</span></span>`,
		`<a href="https://example.com/a">external</a>`,
		`<code>https://tls.example.net:8443/acme/directory</code>`,
		`<a href="https://tls.example.net:8443/cert/x">https://tls.example.net:8443/cert/x</a>`,
		`<pre><code class="language-sh">curl https://tls.example.net:8443/cert/www.example.com`,
		`<div class="doc-table"><table>`, `</table></div>`,
	} {
		if !strings.Contains(p.HTML, want) {
			t.Errorf("guide lacks %s\n%s", want, p.HTML)
		}
	}
	// The contents section is the reader's navigation, not part of the text.
	for _, bad := range []string{"broker.example.com", ".md\"", "<img", "pic.png", `id="contents"`, `<a href="#sub">`} {
		if strings.Contains(p.HTML, bad) {
			t.Errorf("guide contains %q\n%s", bad, p.HTML)
		}
	}
	var toc []string
	for _, h := range p.TOC {
		toc = append(toc, h.ID+"/"+string(rune('0'+h.Level)))
	}
	if strings.Join(toc, ",") != "links-here/2,sub/3,part-two/2" {
		t.Errorf("toc %v", toc)
	}
	// Without an external URL the placeholder stays; the cache keeps the
	// unsubstituted HTML.
	p2, _ := l.Document("")
	if !strings.Contains(p2.HTML, "https://broker.example.com/acme/directory") {
		t.Error("placeholder replaced without an external URL")
	}
	// The substituted URL is escaped.
	p3, _ := l.Document(`https://h.example.com/"x&`)
	if !strings.Contains(p3.HTML, `https://h.example.com/&#34;x&amp;/acme/directory`) {
		t.Errorf("external URL not escaped:\n%s", p3.HTML)
	}
}

func TestLibraryNeverRendersHTML(t *testing.T) {
	fs := mapFS()
	fs[File].Data = []byte("# First\n\n<script>alert(1)</script>\n\n<!-- note -->\n\n" +
		"Inline <b onclick=\"x()\">bold</b> and [js](javascript:alert(1)) and <img src=x onerror=y>.\n")
	p, err := New(fs, quiet).Document("")
	if err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{"<script", "<b ", "onclick", "javascript:", "<img", "onerror"} {
		if strings.Contains(p.HTML, bad) {
			t.Errorf("raw HTML passed through (%s):\n%s", bad, p.HTML)
		}
	}
}

func TestLibraryUnavailable(t *testing.T) {
	for name, l := range map[string]*Library{
		"nil":       New(nil, quiet),
		"empty":     New(fstest.MapFS{}, quiet),
		"missing":   New(os.DirFS(filepath.Join(t.TempDir(), "nope")), quiet),
		"directory": New(fstest.MapFS{File + "/x": {Data: []byte("# X\n")}}, quiet),
		"no title":  New(fstest.MapFS{File: {Data: []byte("## Only a section\n")}}, quiet),
	} {
		if _, err := l.Document(""); !errors.Is(err, ErrUnavailable) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func TestLibraryCacheFollowsTheFile(t *testing.T) {
	fs := mapFS()
	l := New(fs, quiet)
	if p, _ := l.Document(""); !strings.Contains(p.HTML, "Text.") {
		t.Fatal(p.HTML)
	}
	// Same size and time: the cached rendering is used.
	fs[File].Data = []byte(strings.Replace(testGuide, "Text.", "TEXT.", 1))
	if p, _ := l.Document(""); !strings.Contains(p.HTML, "Text.") {
		t.Error("re-rendered although the file looks unchanged")
	}
	// A new modification time renders it again.
	fs[File].ModTime = fs[File].ModTime.Add(time.Second)
	if p, _ := l.Document(""); !strings.Contains(p.HTML, "TEXT.") {
		t.Error("changed file not rendered again")
	}
	// A new size too.
	fs[File].Data = []byte("# User guide\n\nShorter.\n")
	if p, _ := l.Document(""); !strings.Contains(p.HTML, "Shorter.") || len(p.TOC) != 0 {
		t.Errorf("changed size not rendered again: %+v", p)
	}
}

// TestRealGuideRenders renders docs/guide.md the way the image serves it.
func TestRealGuideRenders(t *testing.T) {
	p, err := New(os.DirFS(filepath.Join(repoRoot, guideDir)), quiet).Document("http://192.0.2.10:8081")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(p.HTML, Placeholder) || strings.Contains(p.HTML, "raw HTML omitted") {
		t.Error("placeholder or raw HTML left")
	}
	ids := map[string]bool{}
	for _, h := range p.TOC {
		ids[h.ID] = true
	}
	href := regexp.MustCompile(`href="([^"]*)"`)
	for _, m := range href.FindAllStringSubmatch(p.HTML, -1) {
		h := m[1]
		switch {
		case strings.HasPrefix(h, "#"):
			if !strings.Contains(p.HTML, ` id="`+h[1:]+`"`) {
				t.Errorf("link %q: no such heading in the rendered guide", h)
			}
		case strings.HasPrefix(h, "https://"), strings.HasPrefix(h, "http://192.0.2.10:8081"):
		default:
			t.Errorf("link %q leads outside the reader", h)
		}
	}
	for page, id := range MovedPages {
		if !ids[id] {
			t.Errorf("moved page %s points at #%s, which is not a heading of the guide", page, id)
		}
	}
	if len(p.TOC) < 30 {
		t.Errorf("only %d headings in the navigation", len(p.TOC))
	}
}
