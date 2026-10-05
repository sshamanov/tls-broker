package guide

import (
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
// (GitHub, agents, the in-app reader, a later Confluence export) and
// complete. Paths are relative to this package's directory.
const repoRoot = "../.."

// reservedIDs are element IDs of the UI layout a heading must not take.
var reservedIDs = []string{"main", "side", "side-body", "nav-admin"}

// allowedHosts are the only hosts examples may use besides example.com and
// its subdomains.
var allowedHosts = []string{"acme-v02.api.letsencrypt.org"}

type lintPage struct {
	file  string // file name in docs/guide
	src   []byte
	doc   mdast.Node
	ids   []string
	links []link
}

func loadGuide(t *testing.T) map[string]*lintPage {
	t.Helper()
	dir := filepath.Join(repoRoot, guideDir)
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	pages := map[string]*lintPage{}
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".md") {
			t.Errorf("%s/%s: only Markdown pages belong in the guide", guideDir, e.Name())
			continue
		}
		src, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			t.Fatal(err)
		}
		p := &lintPage{file: e.Name(), src: src}
		var hs []Heading
		p.doc, hs = parse(newMarkdown(), src)
		for _, h := range hs {
			p.ids = append(p.ids, h.ID)
		}
		pages[e.Name()] = p
	}
	return pages
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
	pages := loadGuide(t)
	if _, ok := pages[IndexFile]; !ok {
		t.Fatalf("%s/%s is missing", guideDir, IndexFile)
	}
	hostRe := regexp.MustCompile(`https?://([A-Za-z0-9.-]+)`)
	for name, p := range pages {
		first, _, _ := strings.Cut(string(p.src), "\n")
		if !strings.HasPrefix(first, "# ") {
			t.Errorf("%s: the first line must be the `# Title` (no front matter, no blank line), got %q", name, first)
		}
		h1 := 0
		_ = mdast.Walk(p.doc, func(n mdast.Node, entering bool) (mdast.WalkStatus, error) {
			if !entering {
				return mdast.WalkContinue, nil
			}
			switch n := n.(type) {
			case *mdast.HTMLBlock, *mdast.RawHTML:
				t.Errorf("%s: raw HTML (comments included) is not portable: %q", name, firstLine(n, p.src))
			case *mdast.Image:
				t.Errorf("%s: images are not supported by the reader: %q", name, n.Destination)
			case *mdast.Heading:
				if n.Level == 1 {
					h1++
				}
			case *mdast.Link:
				if l := classify(string(n.Destination)); l.kind == linkExternal && !strings.HasPrefix(string(n.Destination), "https://") {
					t.Errorf("%s: external link %q: use https URLs only", name, n.Destination)
				}
			}
			return mdast.WalkContinue, nil
		})
		if h1 != 1 {
			t.Errorf("%s: %d level-1 headings, want exactly one (the title)", name, h1)
		}
		for _, id := range p.ids {
			if slices.Contains(reservedIDs, id) {
				t.Errorf("%s: heading ID %q collides with the UI layout; rename the heading", name, id)
			}
		}
		for _, m := range hostRe.FindAllStringSubmatch(string(p.src), -1) {
			host := strings.TrimSuffix(strings.ToLower(m[1]), ".")
			if host != "example.com" && !strings.HasSuffix(host, ".example.com") && !slices.Contains(allowedHosts, host) {
				t.Errorf("%s: host %q: examples use broker.example.com and example.com names", name, host)
			}
		}
		if strings.Contains(string(p.src), "://broker.") && !strings.Contains(string(p.src), "https://broker.example.com") {
			t.Errorf("%s: the broker's address must be written https://broker.example.com (the reader substitutes it)", name)
		}
	}
}

func TestGuideLinksResolve(t *testing.T) {
	pages := loadGuide(t)
	for name, p := range pages {
		_ = mdast.Walk(p.doc, func(n mdast.Node, entering bool) (mdast.WalkStatus, error) {
			if l, ok := n.(*mdast.Link); ok && entering {
				p.links = append(p.links, classify(string(l.Destination)))
			}
			return mdast.WalkContinue, nil
		})
		for _, l := range p.links {
			switch l.kind {
			case linkAnchor:
				if !slices.Contains(p.ids, l.fragment) {
					t.Errorf("%s: anchor #%s does not exist on the page", name, l.fragment)
				}
			case linkGuide:
				file := IndexFile
				if l.name != "" {
					file = l.name + ".md"
				}
				target, ok := pages[file]
				if !ok {
					t.Errorf("%s: link to %s: no such guide page", name, file)
					continue
				}
				if l.fragment != "" && !slices.Contains(target.ids, l.fragment) {
					t.Errorf("%s: link to %s#%s: no such heading", name, file, l.fragment)
				}
			case linkRepo:
				if strings.HasPrefix(l.repoPath, "..") {
					t.Errorf("%s: link to %s leaves the repository", name, l.repoPath)
					continue
				}
				if _, err := os.Stat(filepath.Join(repoRoot, l.repoPath)); err != nil {
					t.Errorf("%s: link to %s: %v", name, l.repoPath, err)
					continue
				}
				if l.fragment != "" && !slices.Contains(anchorsOf(t, l.repoPath), l.fragment) {
					t.Errorf("%s: link to %s#%s: no such heading", name, l.repoPath, l.fragment)
				}
			}
		}
	}
}

func TestGuideIndexIsComplete(t *testing.T) {
	pages := loadGuide(t)
	x, err := ParseIndex(pages[IndexFile].src)
	if err != nil {
		t.Fatal(err)
	}
	listed := x.Names()
	if len(listed) == 0 {
		t.Fatal("the index lists no pages")
	}
	for _, n := range listed {
		if _, ok := pages[n+".md"]; !ok {
			t.Errorf("the index lists %s.md, which does not exist", n)
		}
	}
	for file := range pages {
		if file == IndexFile {
			continue
		}
		name := strings.TrimSuffix(file, ".md")
		if !ValidName(name) {
			t.Errorf("%s: page names are lower case letters, digits and dashes", file)
		}
		if !x.Has(name) {
			t.Errorf("%s is not listed in %s, so the reader would not serve it", file, IndexFile)
		}
	}
}

// TestAPIPageCoversRoutes checks that every public route registered in the
// source appears in the API page. The routes are read from the mux
// registrations (internal/app, internal/dnsproxy) and from the path
// constants the ACME server and the direct API switch on.
func TestAPIPageCoversRoutes(t *testing.T) {
	api, err := os.ReadFile(filepath.Join(repoRoot, guideDir, "api.md"))
	if err != nil {
		t.Fatal(err)
	}
	health := stringConsts(t, "internal/httpx/health.go")
	var routes []string
	for _, f := range []string{"internal/app/http.go", "internal/dnsproxy/handler.go"} {
		routes = append(routes, handlePatterns(t, f, health)...)
	}
	acme := stringConsts(t, "internal/acmesrv/server.go")
	for k, v := range acme {
		if strings.HasPrefix(k, "path") && strings.HasPrefix(v, "/") {
			routes = append(routes, acme["PathPrefix"]+v) // "/acme" + "/new-order"
		}
	}
	direct := stringConsts(t, "internal/direct/handler.go")
	routes = append(routes, direct["PathPrefix"]+direct["wildcardPathPrefix"])
	if len(routes) < 20 {
		t.Fatalf("found only %d routes; did the registrations move? %v", len(routes), routes)
	}
	for _, r := range routes {
		if _, p, ok := strings.Cut(r, " "); ok {
			r = p // "POST /dns/present"
		}
		r = strings.TrimSuffix(r, "/")
		if r == "" {
			continue // "/" only redirects to the UI
		}
		if !strings.Contains(string(api), r) {
			t.Errorf("route %s is not documented in %s/api.md", r, guideDir)
		}
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
	read := func(p string) []string {
		b, err := os.ReadFile(filepath.Join(repoRoot, p))
		if err != nil {
			t.Fatal(err)
		}
		var out []string
		for _, m := range re.FindAllString(string(b), -1) {
			out = append(out, strings.TrimSpace(m))
		}
		return out
	}
	g, r := read(path.Join(guideDir, "dns-proxy.md")), read("docs/dns-proxy.md")
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
