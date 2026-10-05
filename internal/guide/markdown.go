// Package guide reads the user guide (docs/guide in the repository,
// /usr/share/tls-broker/docs in the image), renders it for the web UI's
// documentation reader and exports it in Confluence storage format (see
// ExportConfluence).
//
// The guide is plain Markdown that must read the same on GitHub, for agents
// reading the files and in the UI: CommonMark with GFM tables, no raw HTML,
// no front matter, relative .md links between pages. The index page
// (README.md) lists the pages, optionally grouped under headings; only pages
// it lists are served. Heading IDs follow GitHub's rules (see slug), so
// #anchors work the same everywhere.
package guide

import (
	"html"
	"strconv"
	"strings"
	"unicode"

	"github.com/yuin/goldmark"
	"github.com/yuin/goldmark/ast"
	"github.com/yuin/goldmark/extension"
	"github.com/yuin/goldmark/renderer"
	"github.com/yuin/goldmark/text"
	"github.com/yuin/goldmark/util"
)

// IndexFile is the guide's index page: its title, its navigation (the
// relative .md links in its lists) and the page served at the reader's root.
const IndexFile = "README.md"

// newMarkdown is the one Markdown dialect of the guide: CommonMark plus GFM
// (tables, strikethrough, autolinks, task lists). Raw HTML stays disabled
// (goldmark's default; never add html.WithUnsafe): it renders as an HTML
// comment saying it was omitted, and javascript: and similar link targets
// are dropped.
func newMarkdown() goldmark.Markdown {
	return goldmark.New(
		goldmark.WithExtensions(extension.GFM),
		goldmark.WithRendererOptions(renderer.WithNodeRenderers(util.Prioritized(repoRefRenderer{}, 100))),
	)
}

// repoRef replaces a link the reader cannot serve (a file elsewhere in the
// repository) and an image: its children, the link text, stay; with a Path,
// a note names the file in the repository.
type repoRef struct {
	ast.BaseInline
	Path string
}

var kindRepoRef = ast.NewNodeKind("RepoRef")

func (n *repoRef) Kind() ast.NodeKind { return kindRepoRef }

func (n *repoRef) Dump(src []byte, level int) {
	ast.DumpHelper(n, src, level, map[string]string{"Path": n.Path}, nil)
}

type repoRefRenderer struct{}

func (repoRefRenderer) RegisterFuncs(reg renderer.NodeRendererFuncRegisterer) {
	reg.Register(kindRepoRef, func(w util.BufWriter, _ []byte, n ast.Node, entering bool) (ast.WalkStatus, error) {
		ref := n.(*repoRef)
		if ref.Path == "" {
			return ast.WalkContinue, nil
		}
		if entering {
			_, _ = w.WriteString(`<span class="doc-repo">`)
		} else {
			_, _ = w.WriteString(`<span class="doc-repo-path"> (in the repository: <code>` + html.EscapeString(ref.Path) + `</code>)</span></span>`)
		}
		return ast.WalkContinue, nil
	})
}

// Heading is a section heading with its GitHub-compatible ID.
type Heading struct {
	Level int
	Text  string
	ID    string
}

// parse parses src and sets every heading's id attribute the way GitHub
// does. It returns the document and its headings in order.
func parse(md goldmark.Markdown, src []byte) (ast.Node, []Heading) {
	doc := md.Parser().Parse(text.NewReader(src))
	var hs []Heading
	s := newSlugger()
	_ = ast.Walk(doc, func(n ast.Node, entering bool) (ast.WalkStatus, error) {
		h, ok := n.(*ast.Heading)
		if !entering || !ok {
			return ast.WalkContinue, nil
		}
		t := plainText(h, src)
		id := s.slug(t)
		h.SetAttributeString("id", []byte(id))
		hs = append(hs, Heading{Level: h.Level, Text: t, ID: id})
		return ast.WalkSkipChildren, nil
	})
	return doc, hs
}

// plainText is the text of an inline subtree as GitHub would show it: link
// labels without their destinations, code spans without backticks.
func plainText(n ast.Node, src []byte) string {
	var b strings.Builder
	var walk func(ast.Node)
	walk = func(n ast.Node) {
		for c := n.FirstChild(); c != nil; c = c.NextSibling() {
			switch t := c.(type) {
			case *ast.Text:
				b.Write(t.Segment.Value(src))
				if t.SoftLineBreak() || t.HardLineBreak() {
					b.WriteByte(' ')
				}
			case *ast.String:
				b.Write(t.Value)
			case *ast.AutoLink:
				b.Write(t.Label(src))
			default:
				walk(c)
			}
		}
	}
	walk(n)
	return b.String()
}

// slugger makes heading IDs exactly like GitHub (github-slugger): lower
// case; letters, digits, marks, "-" and "_" kept; each space becomes "-";
// everything else dropped; a repeated slug gets "-1", "-2", ...
type slugger struct{ seen map[string]int }

func newSlugger() *slugger { return &slugger{seen: map[string]int{}} }

func (s *slugger) slug(text string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(text) {
		switch {
		case unicode.IsLetter(r), unicode.IsDigit(r), unicode.IsMark(r), r == '-', r == '_':
			b.WriteRune(r)
		case r == ' ':
			b.WriteByte('-')
		}
	}
	base := b.String()
	slug := base
	for {
		if _, dup := s.seen[slug]; !dup {
			break
		}
		s.seen[base]++
		slug = base + "-" + strconv.Itoa(s.seen[base])
	}
	s.seen[slug] = 0
	return slug
}
