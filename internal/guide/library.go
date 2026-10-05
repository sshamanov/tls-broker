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
// docs/guide.md there as File). There is no setting to change it.
const DefaultDir = "/usr/share/tls-broker/docs"

// Placeholder is the broker address the guide's examples use. The reader
// replaces it with the running configuration's server.external_url.
const Placeholder = "https://broker.example.com"

// Base is the reader's URL path.
const Base = "/ui/docs"

// ErrUnavailable: the guide is not present (no readable File with a title).
var ErrUnavailable = errors.New("guide: documentation not available")

// MovedPages maps the names of the pages the guide used to be split into
// (served at Base + "/" + name) to the ID of the level-2 heading that holds
// their text now. The reader redirects the old URLs there; the docs lint
// checks every ID exists.
var MovedPages = map[string]string{
	"getting-started": "getting-started",
	"web-ui":          "using-the-web-interface",
	"acme-proxy":      "acme-proxy-certbot-and-acmesh",
	"dns-proxy":       "dns-proxy-your-own-acme-account",
	"direct":          "direct-download-curl-and-tar",
	"troubleshooting": "troubleshooting",
	"api":             "api-reference",
}

// Page is the rendered guide.
type Page struct {
	Title string // text of the level-1 heading, which is not in HTML
	// HTML is the body without the title and the contents section, broker
	// address substituted; safe to embed.
	HTML string
	// TOC is the level-2 and level-3 headings in order, without the
	// contents heading: the reader shows it as the navigation.
	TOC []Heading
}

// Library reads and renders the guide from a file system (os.DirFS of
// DefaultDir in the image, of docs in tests). The rendering is cached, keyed
// by the file's modification time and size, and done again when the file
// changes; nothing is rendered before it is first requested. It is safe for
// concurrent use.
type Library struct {
	fsys fs.FS
	log  *slog.Logger
	md   goldmark.Markdown

	mu    sync.Mutex
	stamp stamp
	page  *Page

	missingOnce sync.Once
}

type stamp struct {
	mod  time.Time
	size int64
}

// New returns a library over fsys; a nil fsys is a build without docs.
func New(fsys fs.FS, logger *slog.Logger) *Library {
	if logger == nil {
		logger = slog.Default()
	}
	return &Library{fsys: fsys, log: logger, md: newMarkdown()}
}

// Document returns the guide with Placeholder replaced by externalURL (no
// trailing slash; "" leaves the placeholder), or ErrUnavailable.
func (l *Library) Document(externalURL string) (*Page, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.fsys == nil {
		l.unavailable(errors.New("no documentation directory"))
		return nil, ErrUnavailable
	}
	st, err := l.stat()
	if err != nil {
		l.unavailable(err)
		return nil, ErrUnavailable
	}
	if l.page == nil || l.stamp != st {
		src, err := fs.ReadFile(l.fsys, File)
		if err != nil {
			l.unavailable(err)
			return nil, ErrUnavailable
		}
		p := l.render(src)
		if p.Title == "" {
			l.unavailable(errors.New("the guide has no level-1 heading"))
			return nil, ErrUnavailable
		}
		l.page, l.stamp = &p, st
	}
	p := *l.page
	if ext := strings.TrimRight(externalURL, "/"); ext != "" {
		p.HTML = strings.ReplaceAll(p.HTML, Placeholder, html.EscapeString(ext))
	}
	return &p, nil
}

func (l *Library) stat() (stamp, error) {
	fi, err := fs.Stat(l.fsys, File)
	if err != nil {
		return stamp{}, err
	}
	if fi.IsDir() {
		return stamp{}, fs.ErrNotExist
	}
	return stamp{fi.ModTime(), fi.Size()}, nil
}

func (l *Library) unavailable(err error) {
	l.missingOnce.Do(func() {
		l.log.Warn("guide: documentation is not available in this build", "dir", DefaultDir, "file", File, "error", err)
	})
}

// render turns the guide into HTML for the reader: heading IDs as on
// GitHub, the title heading and the contents section taken out (the reader
// shows the headings as its navigation), links into the repository shown as
// text with the repository path (the reader does not serve them), images as
// their text. Raw HTML in the source is never passed through.
func (l *Library) render(src []byte) Page {
	doc, hs := parse(l.md, src)
	var p Page
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
	contentsID := ""
	if h, blocks := contentsSection(doc, src); h != nil {
		contentsID = headingID(h)
		for _, b := range append(blocks, h) {
			doc.RemoveChild(doc, b)
		}
	}
	for _, h := range hs {
		if (h.Level == 2 || h.Level == 3) && h.ID != contentsID {
			p.TOC = append(p.TOC, h)
		}
	}
	for _, n := range links {
		if lk := classify(string(n.Destination)); lk.kind == linkRepo {
			replaceInline(n, &repoRef{Path: lk.repoPath})
		}
	}
	for _, n := range images {
		replaceInline(n, &repoRef{})
	}
	var buf bytes.Buffer
	if err := l.md.Renderer().Render(&buf, src, doc); err != nil {
		l.log.Error("guide: render failed", "error", err)
	}
	// Tables scroll inside a wrapper so their header and body stay one
	// table. Raw HTML never reaches the output, so every "<table>" here is
	// the renderer's own.
	p.HTML = strings.ReplaceAll(strings.ReplaceAll(buf.String(),
		"<table>", `<div class="doc-table"><table>`), "</table>", "</table></div>")
	return p
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
