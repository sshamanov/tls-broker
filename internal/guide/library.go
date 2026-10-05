package guide

import (
	"bytes"
	"errors"
	"html"
	"io/fs"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/yuin/goldmark"
	"github.com/yuin/goldmark/ast"
)

// DefaultDir is where the image ships the guide (deploy/Dockerfile copies
// docs/guide there). There is no setting to change it.
const DefaultDir = "/usr/share/tls-broker/docs"

// Placeholder is the broker address the guide's examples use. The reader
// replaces it with the running configuration's server.external_url.
const Placeholder = "https://broker.example.com"

// Base is the reader's URL path; a page is served at Base + "/" + name.
const Base = "/ui/docs"

var (
	// ErrUnavailable: the guide is not present (no readable index page).
	ErrUnavailable = errors.New("guide: documentation not available")
	// ErrNotFound: the page is not listed in the index, or its file is
	// missing.
	ErrNotFound = errors.New("guide: no such page")
)

// Page is a rendered guide page.
type Page struct {
	Name  string    // "" for the index page
	Title string    // text of the level-1 heading, which is not in HTML
	HTML  string    // the body, broker address substituted; safe to embed
	TOC   []Heading // level-2 and level-3 headings, in order
}

// Library reads and renders the guide from a file system (os.DirFS of
// DefaultDir in the image, of docs/guide in tests). Rendered pages are
// cached per file, keyed by modification time and size, and rendered again
// when the file or the index changes; nothing is rendered before it is
// first requested. It is safe for concurrent use.
type Library struct {
	fsys fs.FS
	log  *slog.Logger
	md   goldmark.Markdown

	mu    sync.Mutex
	index *cachedIndex
	pages map[string]*cachedPage

	missingOnce sync.Once
}

type stamp struct {
	mod  time.Time
	size int64
}

type cachedIndex struct {
	stamp stamp
	index Index
	page  Page // the index page itself
}

type cachedPage struct {
	stamp stamp
	index stamp // the index it was rendered against (link targets)
	page  Page
}

// New returns a library over fsys; a nil fsys is a build without docs.
func New(fsys fs.FS, logger *slog.Logger) *Library {
	if logger == nil {
		logger = slog.Default()
	}
	return &Library{fsys: fsys, log: logger, md: newMarkdown(), pages: map[string]*cachedPage{}}
}

// Index returns the parsed index, or ErrUnavailable.
func (l *Library) Index() (Index, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	ci, err := l.loadIndex()
	if err != nil {
		return Index{}, err
	}
	return ci.index, nil
}

// Page returns the page name ("" for the index page) with Placeholder
// replaced by externalURL (no trailing slash; "" leaves the placeholder).
// Only pages the index lists are served: anything else is ErrNotFound.
func (l *Library) Page(name, externalURL string) (*Page, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	ci, err := l.loadIndex()
	if err != nil {
		return nil, err
	}
	p := ci.page
	if name != "" {
		if !ValidName(name) || !ci.index.Has(name) {
			return nil, ErrNotFound
		}
		file := name + ".md"
		st, err := l.stat(file)
		if err != nil {
			l.log.Warn("guide: page listed in the index is missing", "page", file, "error", err)
			return nil, ErrNotFound
		}
		c := l.pages[name]
		if c == nil || c.stamp != st || c.index != ci.stamp {
			src, err := fs.ReadFile(l.fsys, file)
			if err != nil {
				l.log.Warn("guide: cannot read page", "page", file, "error", err)
				return nil, ErrNotFound
			}
			c = &cachedPage{stamp: st, index: ci.stamp, page: l.render(name, src, ci.index)}
			l.pages[name] = c
		}
		p = c.page
	}
	if ext := strings.TrimRight(externalURL, "/"); ext != "" {
		p.HTML = strings.ReplaceAll(p.HTML, Placeholder, html.EscapeString(ext))
	}
	return &p, nil
}

func (l *Library) stat(file string) (stamp, error) {
	fi, err := fs.Stat(l.fsys, file)
	if err != nil {
		return stamp{}, err
	}
	if fi.IsDir() {
		return stamp{}, fs.ErrNotExist
	}
	return stamp{fi.ModTime(), fi.Size()}, nil
}

// loadIndex returns the cached index, reading it again when it changed.
// Callers hold l.mu.
func (l *Library) loadIndex() (*cachedIndex, error) {
	if l.fsys == nil {
		l.unavailable(errors.New("no documentation directory"))
		return nil, ErrUnavailable
	}
	st, err := l.stat(IndexFile)
	if err != nil {
		l.unavailable(err)
		return nil, ErrUnavailable
	}
	if l.index != nil && l.index.stamp == st {
		return l.index, nil
	}
	src, err := fs.ReadFile(l.fsys, IndexFile)
	if err != nil {
		l.unavailable(err)
		return nil, ErrUnavailable
	}
	idx, err := ParseIndex(src)
	if err != nil {
		l.unavailable(err)
		return nil, ErrUnavailable
	}
	l.index = &cachedIndex{stamp: st, index: idx, page: l.render("", src, idx)}
	return l.index, nil
}

func (l *Library) unavailable(err error) {
	l.missingOnce.Do(func() {
		l.log.Warn("guide: documentation is not available in this build", "dir", DefaultDir, "error", err)
	})
}

// render turns a guide page into HTML for the reader: heading IDs as on
// GitHub, the title heading taken out, links to listed guide pages pointed at
// the reader, links to anything else in the repository shown as text with
// the repository path (the reader does not serve them), images as their
// text. Raw HTML in the source is never passed through.
func (l *Library) render(name string, src []byte, idx Index) Page {
	doc, hs := parse(l.md, src)
	p := Page{Name: name}
	var title ast.Node
	var links []*ast.Link
	var images []*ast.Image
	_ = ast.Walk(doc, func(n ast.Node, entering bool) (ast.WalkStatus, error) {
		if !entering {
			return ast.WalkContinue, nil
		}
		switch n := n.(type) {
		case *ast.Heading:
			if n.Level == 1 && title == nil {
				title = n
				p.Title = plainText(n, src)
			}
		case *ast.Link:
			links = append(links, n)
		case *ast.Image:
			images = append(images, n)
		}
		return ast.WalkContinue, nil
	})
	if title != nil {
		title.Parent().RemoveChild(title.Parent(), title)
	}
	for _, h := range hs {
		if h.Level == 2 || h.Level == 3 {
			p.TOC = append(p.TOC, h)
		}
	}
	for _, n := range links {
		lk := classify(string(n.Destination))
		switch {
		case lk.kind == linkGuide && lk.name == "":
			n.Destination = []byte(withFragment(Base, lk.fragment))
		case lk.kind == linkGuide && idx.Has(lk.name):
			n.Destination = []byte(withFragment(Base+"/"+lk.name, lk.fragment))
		case lk.kind == linkGuide, lk.kind == linkRepo:
			replaceInline(n, &repoRef{Path: lk.repoPath})
		}
	}
	for _, n := range images {
		replaceInline(n, &repoRef{})
	}
	var buf bytes.Buffer
	if err := l.md.Renderer().Render(&buf, src, doc); err != nil {
		l.log.Error("guide: render failed", "page", name, "error", err)
	}
	// Tables scroll inside a wrapper so their header and body stay one
	// table. Raw HTML never reaches the output, so every "<table>" here is
	// the renderer's own.
	p.HTML = strings.ReplaceAll(strings.ReplaceAll(buf.String(),
		"<table>", `<div class="doc-table"><table>`), "</table>", "</table></div>")
	if p.Title == "" {
		p.Title = name
	}
	return p
}

func withFragment(path, fragment string) string {
	if fragment == "" {
		return path
	}
	return path + "#" + fragment
}

// replaceInline puts with in place of n and moves n's children into it.
func replaceInline(n ast.Node, with ast.Node) {
	for c := n.FirstChild(); c != nil; {
		next := c.NextSibling()
		with.AppendChild(with, c)
		c = next
	}
	n.Parent().ReplaceChild(n.Parent(), n, with)
}
