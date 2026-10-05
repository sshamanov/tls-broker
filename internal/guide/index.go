package guide

import (
	"errors"
	"net/url"
	"path"
	"regexp"
	"strings"

	"github.com/yuin/goldmark/ast"
)

// Entry is one page of the index: its file name without ".md" and the link
// text the index gives it.
type Entry struct {
	Name  string
	Title string
}

// Group is a run of index entries under one heading (Title is empty for
// entries before the first heading below the title).
type Group struct {
	Title   string
	Entries []Entry
}

// Index is the parsed index page.
type Index struct {
	Title  string
	Groups []Group
}

// Has reports whether the index lists the page name.
func (x Index) Has(name string) bool {
	for _, g := range x.Groups {
		for _, e := range g.Entries {
			if e.Name == name {
				return true
			}
		}
	}
	return false
}

// Names are the listed pages in index order.
func (x Index) Names() []string {
	var out []string
	for _, g := range x.Groups {
		for _, e := range g.Entries {
			out = append(out, e.Name)
		}
	}
	return out
}

// pageName is what a guide page's file name (without ".md") must look like.
var pageName = regexp.MustCompile(`^[a-z0-9][a-z0-9-]*$`)

// ValidName reports whether name can be a guide page (not the index).
func ValidName(name string) bool { return pageName.MatchString(name) }

// ParseIndex reads the index page: the first level-1 heading is the title,
// every later heading starts a group, and every link to a guide page inside a
// list is an entry (in order, each page once).
func ParseIndex(src []byte) (Index, error) {
	doc, _ := parse(newMarkdown(), src)
	var x Index
	seen := map[string]bool{}
	cur := -1
	_ = ast.Walk(doc, func(n ast.Node, entering bool) (ast.WalkStatus, error) {
		if !entering {
			return ast.WalkContinue, nil
		}
		switch n := n.(type) {
		case *ast.Heading:
			t := plainText(n, src)
			if n.Level == 1 && x.Title == "" {
				x.Title = t
			} else {
				x.Groups = append(x.Groups, Group{Title: t})
				cur = len(x.Groups) - 1
			}
			return ast.WalkSkipChildren, nil
		case *ast.Link:
			l := classify(string(n.Destination))
			if l.kind != linkGuide || l.name == "" || seen[l.name] || !inList(n) {
				return ast.WalkContinue, nil
			}
			if cur < 0 {
				x.Groups = append(x.Groups, Group{})
				cur = 0
			}
			seen[l.name] = true
			x.Groups[cur].Entries = append(x.Groups[cur].Entries, Entry{Name: l.name, Title: plainText(n, src)})
		}
		return ast.WalkContinue, nil
	})
	// Drop headings that list nothing (for example an introduction).
	groups := x.Groups[:0]
	for _, g := range x.Groups {
		if len(g.Entries) > 0 {
			groups = append(groups, g)
		}
	}
	x.Groups = groups
	if x.Title == "" {
		return x, errors.New("guide: the index has no title")
	}
	return x, nil
}

func inList(n ast.Node) bool {
	for p := n.Parent(); p != nil; p = p.Parent() {
		if p.Kind() == ast.KindListItem {
			return true
		}
	}
	return false
}

type linkKind int

const (
	// linkAnchor: "#section" on the same page.
	linkAnchor linkKind = iota
	// linkExternal: an absolute URL (any scheme) or a protocol-relative one.
	linkExternal
	// linkGuide: another page of the guide ("acme-proxy.md#x"), or the index
	// ("README.md", name "").
	linkGuide
	// linkRepo: any other relative path; it resolves inside the repository
	// only and is not served by the reader.
	linkRepo
)

type link struct {
	kind     linkKind
	name     string // linkGuide: page name, "" for the index
	repoPath string // linkRepo, linkGuide: path from the repository root
	fragment string // without "#"
}

// guideDir is where the guide lives in the repository.
const guideDir = "docs/guide"

// classify sorts a link destination as written in a guide page.
func classify(dest string) link {
	if strings.HasPrefix(dest, "#") {
		return link{kind: linkAnchor, fragment: dest[1:]}
	}
	u, err := url.Parse(dest)
	if err != nil || u.Scheme != "" || u.Host != "" || strings.HasPrefix(dest, "//") {
		return link{kind: linkExternal}
	}
	l := link{fragment: u.Fragment, repoPath: path.Join(guideDir, u.Path)}
	if !strings.Contains(u.Path, "/") && strings.HasSuffix(u.Path, ".md") {
		if u.Path == IndexFile {
			l.kind = linkGuide
			return l
		}
		if name := strings.TrimSuffix(u.Path, ".md"); ValidName(name) {
			l.kind, l.name = linkGuide, name
			return l
		}
	}
	l.kind = linkRepo
	return l
}
