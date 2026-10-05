package guide

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"

	mdast "github.com/yuin/goldmark/ast"
)

// The docs lint: the guide in the repository must stay portable Markdown
// (GitHub, agents, the in-app reader, Confluence), one document whose
// contents list matches its headings. Paths are relative to this package's
// directory.
const repoRoot = "../.."

// reservedIDs are element IDs of the UI layout a heading must not take.
var reservedIDs = []string{"main", "side", "side-body", "nav-admin", "docs-nav-title"}

// allowedHosts are the only hosts examples may use besides example.com and
// its subdomains.
var allowedHosts = []string{"acme-v02.api.letsencrypt.org"}

type lintGuide struct {
	src []byte
	doc mdast.Node
	hs  []Heading
}

func loadGuide(t *testing.T) *lintGuide {
	t.Helper()
	src, err := os.ReadFile(filepath.Join(repoRoot, guideDir, File))
	if err != nil {
		t.Fatal(err)
	}
	g := &lintGuide{src: src}
	g.doc, g.hs = parse(newMarkdown(), src)
	return g
}

func (g *lintGuide) ids() []string {
	var ids []string
	for _, h := range g.hs {
		ids = append(ids, h.ID)
	}
	return ids
}

// anchorsOf returns the heading IDs of a repository Markdown file.
func anchorsOf(t *testing.T, repoPath string) []string {
	t.Helper()
	src, err := os.ReadFile(filepath.Join(repoRoot, repoPath))
	if err != nil {
		return nil
	}
	_, hs := parse(newMarkdown(), src)
	var ids []string
	for _, h := range hs {
		ids = append(ids, h.ID)
	}
	return ids
}

func TestGuideIsPortableMarkdown(t *testing.T) {
	g := loadGuide(t)
	if _, err := os.Stat(filepath.Join(repoRoot, guideDir, "guide")); err == nil {
		t.Errorf("%s/guide exists: the guide is the single file %s/%s", guideDir, guideDir, File)
	}
	hostRe := regexp.MustCompile(`https?://([A-Za-z0-9.-]+)`)
	first, _, _ := strings.Cut(string(g.src), "\n")
	if !strings.HasPrefix(first, "# ") {
		t.Errorf("the first line must be the `# Title` (no front matter, no blank line), got %q", first)
	}
	h1 := 0
	_ = mdast.Walk(g.doc, func(n mdast.Node, entering bool) (mdast.WalkStatus, error) {
		if !entering {
			return mdast.WalkContinue, nil
		}
		switch n := n.(type) {
		case *mdast.HTMLBlock, *mdast.RawHTML:
			t.Errorf("raw HTML (comments included) is not portable: %q", firstLine(n, g.src))
		case *mdast.Image:
			t.Errorf("images are not supported by the reader: %q", n.Destination)
		case *mdast.Heading:
			if n.Level == 1 {
				h1++
			}
		case *mdast.Link:
			if l := classify(string(n.Destination)); l.kind == linkExternal && !strings.HasPrefix(string(n.Destination), "https://") {
				t.Errorf("external link %q: use https URLs only", n.Destination)
			}
		}
		return mdast.WalkContinue, nil
	})
	if h1 != 1 {
		t.Errorf("%d level-1 headings, want exactly one (the title)", h1)
	}
	seen := map[string]bool{}
	for _, h := range g.hs {
		if slices.Contains(reservedIDs, h.ID) {
			t.Errorf("heading ID %q collides with the UI layout; rename the heading", h.ID)
		}
		if seen[h.Text] {
			t.Errorf("heading %q appears twice; give each section a distinct heading so its anchor is readable", h.Text)
		}
		seen[h.Text] = true
	}
	for _, m := range hostRe.FindAllStringSubmatch(string(g.src), -1) {
		host := strings.TrimSuffix(strings.ToLower(m[1]), ".")
		if host != "example.com" && !strings.HasSuffix(host, ".example.com") && !slices.Contains(allowedHosts, host) {
			t.Errorf("host %q: examples use broker.example.com and example.com names", host)
		}
	}
	if strings.Contains(string(g.src), "://broker.") && !strings.Contains(string(g.src), "https://broker.example.com") {
		t.Error("the broker's address must be written https://broker.example.com (the reader substitutes it)")
	}
}

func TestGuideLinksResolve(t *testing.T) {
	g := loadGuide(t)
	ids := g.ids()
	_ = mdast.Walk(g.doc, func(n mdast.Node, entering bool) (mdast.WalkStatus, error) {
		ln, ok := n.(*mdast.Link)
		if !ok || !entering {
			return mdast.WalkContinue, nil
		}
		l := classify(string(ln.Destination))
		switch l.kind {
		case linkAnchor:
			if !slices.Contains(ids, l.fragment) {
				t.Errorf("anchor #%s: no such heading", l.fragment)
			}
		case linkRepo:
			switch {
			case l.repoPath == path.Join(guideDir, File):
				t.Errorf("link %q to the guide itself: write #anchor", ln.Destination)
			case strings.HasPrefix(l.repoPath, ".."):
				t.Errorf("link to %s leaves the repository", l.repoPath)
			default:
				if _, err := os.Stat(filepath.Join(repoRoot, l.repoPath)); err != nil {
					t.Errorf("link to %s: %v", l.repoPath, err)
				} else if l.fragment != "" && !slices.Contains(anchorsOf(t, l.repoPath), l.fragment) {
					t.Errorf("link to %s#%s: no such heading", l.repoPath, l.fragment)
				}
			}
		}
		return mdast.WalkContinue, nil
	})
}

// TestGuideContentsMatchHeadings: the contents section (a list of links to
// the level-2 headings, each with a nested list of links to its level-3
// headings) lists exactly the document's level-2 and level-3 headings after
// it, in order, with their text and anchors.
func TestGuideContentsMatchHeadings(t *testing.T) {
	g := loadGuide(t)
	h, blocks := contentsSection(g.doc, g.src)
	if h == nil {
		t.Fatalf("no level-2 heading %q", ContentsTitle)
	}
	if prev := h.PreviousSibling(); prev == nil {
		t.Fatal("the contents section must follow the title and introduction")
	} else {
		for n := prev; n != nil; n = n.PreviousSibling() {
			if hd, ok := n.(*mdast.Heading); ok && hd.Level != 1 {
				t.Errorf("heading %q comes before the contents section", plainText(hd, g.src))
			}
		}
	}
	if len(blocks) != 1 || blocks[0].Kind() != mdast.KindList {
		t.Fatalf("the contents section must be exactly one list, got %d blocks", len(blocks))
	}
	var listed []string
	var walk func(list mdast.Node, level int)
	walk = func(list mdast.Node, level int) {
		for item := list.FirstChild(); item != nil; item = item.NextSibling() {
			var entry string
			for c := item.FirstChild(); c != nil; c = c.NextSibling() {
				switch c.Kind() {
				case mdast.KindParagraph, mdast.KindTextBlock:
					ln, ok := c.FirstChild().(*mdast.Link)
					if !ok || ln.NextSibling() != nil {
						t.Errorf("contents entry %q must be one link and nothing else", plainText(c, g.src))
						continue
					}
					l := classify(string(ln.Destination))
					if l.kind != linkAnchor {
						t.Errorf("contents entry %q: link to a heading as #anchor", plainText(ln, g.src))
					}
					entry = fmt.Sprintf("%d %s #%s", level, plainText(ln, g.src), l.fragment)
					listed = append(listed, entry)
				case mdast.KindList:
					if level == 3 {
						t.Errorf("contents entry nested below level 3")
						continue
					}
					walk(c, level+1)
				}
			}
			if entry == "" {
				t.Errorf("contents list item without a link")
			}
		}
	}
	walk(blocks[0], 2)
	var want []string
	contentsID := headingID(h)
	for _, hd := range g.hs {
		if (hd.Level == 2 || hd.Level == 3) && hd.ID != contentsID {
			want = append(want, fmt.Sprintf("%d %s #%s", hd.Level, hd.Text, hd.ID))
		}
	}
	if !slices.Equal(listed, want) {
		t.Errorf("the contents list does not match the headings\nlisted:\n  %s\nheadings:\n  %s",
			strings.Join(listed, "\n  "), strings.Join(want, "\n  "))
	}
}

// TestMovedPagesExist: every former page name redirects to a level-2
// heading of the guide.
func TestMovedPagesExist(t *testing.T) {
	g := loadGuide(t)
	for page, id := range MovedPages {
		found := false
		for _, h := range g.hs {
			found = found || (h.Level == 2 && h.ID == id)
		}
		if !found {
			t.Errorf("moved page %s: #%s is not a level-2 heading of the guide", page, id)
		}
	}
}

// section returns the text of the level-2 section titled title: from its
// heading up to the next level-2 heading.
func (g *lintGuide) section(t *testing.T, title string) string {
	t.Helper()
	lines := strings.Split(string(g.src), "\n")
	start := slices.Index(lines, "## "+title)
	if start < 0 {
		t.Fatalf("no section %q in the guide", title)
	}
	end := len(lines)
	for i := start + 1; i < len(lines); i++ {
		if strings.HasPrefix(lines[i], "## ") {
			end = i
			break
		}
	}
	return strings.Join(lines[start:end], "\n")
}

// TestAPICoversClientRoutes checks that the guide's API section documents
// every route a user's machine calls: each route the app mounts except the
// operator ones (notInGuide), every DNS proxy route, the ACME directory and
// the direct download path. Routes left out of the guide must be documented
// in their reference instead: the ACME resources (clients find them through
// the directory) in docs/acme-proxy.md, the direct wildcard path in
// docs/direct-api.md, health and metrics in docs/observability.md. The
// routes are read from the mux registrations (internal/app,
// internal/dnsproxy) and from the path constants the ACME server and the
// direct API switch on.
func TestAPICoversClientRoutes(t *testing.T) {
	api := loadGuide(t).section(t, "API")
	health := stringConsts(t, "internal/httpx/health.go")
	acme := stringConsts(t, "internal/acmesrv/server.go")
	direct := stringConsts(t, "internal/direct/handler.go")
	// Operator and web interface routes: not for users' machines.
	notInGuide := map[string]string{
		"/ui/": "", "/ui": "", "/": "", // the web interface; "/" redirects to it
		"/metrics":           "docs/observability.md",
		health["HealthPath"]: "docs/observability.md",
	}
	var guide []string
	for _, r := range handlePatterns(t, "internal/app/http.go", health) {
		if ref, ok := notInGuide[r]; ok {
			if ref != "" {
				mustMention(t, ref, r)
			}
			continue
		}
		guide = append(guide, r)
	}
	guide = append(guide, handlePatterns(t, "internal/dnsproxy/handler.go", nil)...)
	guide = append(guide, acme["PathPrefix"]+acme["pathDirectory"], direct["PathPrefix"]+"{name}")
	if len(guide) < 9 {
		t.Fatalf("found only %d client routes; did the registrations move? %v", len(guide), guide)
	}
	for _, r := range guide {
		if _, p, ok := strings.Cut(r, " "); ok {
			r = p // "POST /dns/present"
		}
		if !strings.Contains(api, strings.TrimSuffix(r, "/")) {
			t.Errorf("route %s is not documented in the API section of %s/%s", r, guideDir, File)
		}
	}
	// Every ACME resource is in the ACME proxy reference's endpoint table.
	n := 0
	for k, v := range acme {
		if strings.HasPrefix(k, "path") && strings.HasPrefix(v, "/") {
			mustMention(t, "docs/acme-proxy.md", strings.TrimSuffix(acme["PathPrefix"]+v, "/"))
			n++
		}
	}
	if n < 10 {
		t.Fatalf("found only %d ACME paths; did the constants move?", n)
	}
	// The wildcard path is for admins and the wildcard role only, so the
	// user guide leaves it out on purpose; its reference documents it.
	wild := direct["PathPrefix"] + direct["wildcardPathPrefix"]
	mustMention(t, "docs/direct-api.md", wild)
	if strings.Contains(string(loadGuide(t).src), wild) {
		t.Errorf("the user guide documents %s; it is for admins and the wildcard role only", wild)
	}
}

// mustMention fails unless the repository file mentions s.
func mustMention(t *testing.T, file, s string) {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(repoRoot, file))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), s) {
		t.Errorf("%s is not documented in %s", s, file)
	}
}

// stringConsts returns the string constants declared in a Go file.
func stringConsts(t *testing.T, file string) map[string]string {
	t.Helper()
	f := parseGo(t, file)
	out := map[string]string{}
	for _, d := range f.Decls {
		g, ok := d.(*ast.GenDecl)
		if !ok || g.Tok != token.CONST {
			continue
		}
		for _, s := range g.Specs {
			vs := s.(*ast.ValueSpec)
			for i, n := range vs.Names {
				if i < len(vs.Values) {
					if lit, ok := vs.Values[i].(*ast.BasicLit); ok && lit.Kind == token.STRING {
						v, _ := strconv.Unquote(lit.Value)
						out[n.Name] = v
					}
				}
			}
		}
	}
	return out
}

// handlePatterns returns the first argument of every Handle/HandleFunc call
// in a Go file, resolving constants through consts.
func handlePatterns(t *testing.T, file string, consts map[string]string) []string {
	t.Helper()
	var out []string
	ast.Inspect(parseGo(t, file), func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok || len(call.Args) == 0 {
			return true
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok || (sel.Sel.Name != "Handle" && sel.Sel.Name != "HandleFunc") {
			return true
		}
		switch a := call.Args[0].(type) {
		case *ast.BasicLit:
			v, _ := strconv.Unquote(a.Value)
			out = append(out, v)
		case *ast.SelectorExpr:
			v, ok := consts[a.Sel.Name]
			if !ok {
				t.Errorf("%s: cannot resolve route %s.%s", file, a.X, a.Sel.Name)
			}
			out = append(out, v)
		default:
			t.Errorf("%s: route registered with a non-constant pattern", file)
		}
		return true
	})
	return out
}

func parseGo(t *testing.T, file string) *ast.File {
	t.Helper()
	f, err := parser.ParseFile(token.NewFileSet(), filepath.Join(repoRoot, file), nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	return f
}

// TestCertbotHooksMatchReference keeps the Certbot DNS-proxy hooks of the
// guide identical to the reference (docs/dns-proxy.md); test/compat runs the
// guide's lines verbatim.
func TestCertbotHooksMatchReference(t *testing.T) {
	re := regexp.MustCompile(`(?m)^ *--manual-(?:auth|cleanup)-hook '.*' \\$`)
	read := func(text string) []string {
		var out []string
		for _, m := range re.FindAllString(text, -1) {
			out = append(out, strings.TrimSpace(m))
		}
		return out
	}
	ref, err := os.ReadFile(filepath.Join(repoRoot, "docs/dns-proxy.md"))
	if err != nil {
		t.Fatal(err)
	}
	g, r := read(string(loadGuide(t).src)), read(string(ref))
	if len(g) != 2 || !slices.Equal(g, r) {
		t.Errorf("certbot hooks differ:\nguide:     %q\nreference: %q", g, r)
	}
}

func firstLine(n mdast.Node, src []byte) string {
	if l := n.Lines(); l != nil && l.Len() > 0 {
		s := l.At(0)
		return strings.TrimSpace(string(s.Value(src)))
	}
	if r, ok := n.(*mdast.RawHTML); ok && r.Segments.Len() > 0 {
		s := r.Segments.At(0)
		return string(s.Value(src))
	}
	return ""
}
