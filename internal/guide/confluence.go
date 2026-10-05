package guide

import (
	"bytes"
	"errors"
	"fmt"
	"html"
	"io/fs"
	"strings"

	"github.com/yuin/goldmark"
	"github.com/yuin/goldmark/ast"
	"github.com/yuin/goldmark/extension"
	east "github.com/yuin/goldmark/extension/ast"
	"github.com/yuin/goldmark/renderer"
	ghtml "github.com/yuin/goldmark/renderer/html"
	"github.com/yuin/goldmark/util"
)

// Confluence storage format export of the guide (used by "tls-broker docs
// publish"). It parses the guide with the reader's dialect and heading IDs
// and renders XHTML in Confluence's storage format: fenced code as the code
// macro, tables as plain tables, links between guide pages as Confluence page
// links, every heading carrying an anchor macro named by its GitHub slug (so
// "page.md#anchor" links keep working), links into the rest of the
// repository as text naming the file, like the reader.

// ConfluenceOptions control the export.
type ConfluenceOptions struct {
	// ExternalURL replaces Placeholder (trailing "/" dropped); "" leaves it.
	ExternalURL string
	// IndexTitle is the title of the Confluence page that holds the index.
	IndexTitle string
	// TitlePrefix is put before a page's level-1 heading to make its
	// Confluence title.
	TitlePrefix string
	// Note, when not empty, is shown in an info macro at the top of every
	// page.
	Note string
}

// StoragePage is one guide page in Confluence storage format.
type StoragePage struct {
	Name  string // "" for the index page
	File  string // file name in the guide directory
	Title string // Confluence page title
	Body  string // storage-format XHTML
}

// ExportConfluence renders the index (first) and every page it lists, in
// index order. A listed page that is missing or has no title is an error, as
// are two pages with the same Confluence title.
func ExportConfluence(fsys fs.FS, opts ConfluenceOptions) ([]StoragePage, error) {
	if fsys == nil {
		return nil, ErrUnavailable
	}
	isrc, err := fs.ReadFile(fsys, IndexFile)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrUnavailable, err)
	}
	idx, err := ParseIndex(isrc)
	if err != nil {
		return nil, err
	}
	if opts.IndexTitle == "" {
		return nil, errors.New("guide: the index page needs a Confluence title")
	}
	pages := []StoragePage{{Name: "", File: IndexFile, Title: opts.IndexTitle}}
	srcs := [][]byte{isrc}
	titles := map[string]string{"": opts.IndexTitle}
	seen := map[string]string{opts.IndexTitle: IndexFile}
	for _, name := range idx.Names() {
		file := name + ".md"
		src, err := fs.ReadFile(fsys, file)
		if err != nil {
			return nil, fmt.Errorf("guide: page %s listed in the index: %w", file, err)
		}
		h1 := firstTitle(src)
		if h1 == "" {
			return nil, fmt.Errorf("guide: page %s has no level-1 heading", file)
		}
		title := opts.TitlePrefix + h1
		if other, dup := seen[title]; dup {
			return nil, fmt.Errorf("guide: pages %s and %s would both be titled %q", other, file, title)
		}
		seen[title] = file
		titles[name] = title
		pages = append(pages, StoragePage{Name: name, File: file, Title: title})
		srcs = append(srcs, src)
	}
	c := &storageConverter{opts: opts, titles: titles}
	c.md = newStorageMarkdown(c.sub)
	for i := range pages {
		pages[i].Body = c.render(srcs[i])
	}
	return pages, nil
}

// firstTitle is the text of the first level-1 heading.
func firstTitle(src []byte) string {
	doc, _ := parse(newMarkdown(), src)
	var t string
	_ = ast.Walk(doc, func(n ast.Node, entering bool) (ast.WalkStatus, error) {
		if h, ok := n.(*ast.Heading); ok && entering && h.Level == 1 && t == "" {
			t = plainText(h, src)
			return ast.WalkStop, nil
		}
		return ast.WalkContinue, nil
	})
	return t
}

// newStorageMarkdown parses exactly like newMarkdown (CommonMark + GFM, raw
// HTML disabled) and renders XHTML with the storage-format node renderers;
// sub is applied to code block text, which is written raw (CDATA).
func newStorageMarkdown(sub func(string) string) goldmark.Markdown {
	return goldmark.New(
		goldmark.WithExtensions(extension.GFM),
		goldmark.WithRendererOptions(ghtml.WithXHTML(),
			renderer.WithNodeRenderers(util.Prioritized(storageRenderer{sub: sub}, 100))),
	)
}

type storageConverter struct {
	opts   ConfluenceOptions
	titles map[string]string // page name ("" index) -> Confluence title
	md     goldmark.Markdown
}

// sub replaces the placeholder in raw text (code, CDATA).
func (c *storageConverter) sub(s string) string {
	if ext := strings.TrimRight(c.opts.ExternalURL, "/"); ext != "" {
		return strings.ReplaceAll(s, Placeholder, ext)
	}
	return s
}

func (c *storageConverter) render(src []byte) string {
	doc, _ := parse(c.md, src)
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
	for _, n := range links {
		lk := classify(string(n.Destination))
		text := c.sub(plainText(n, src))
		switch {
		case lk.kind == linkAnchor:
			n.Parent().ReplaceChild(n.Parent(), n, &pageLink{Anchor: lk.fragment, Label: text})
		case lk.kind == linkGuide && c.titles[lk.name] != "":
			n.Parent().ReplaceChild(n.Parent(), n, &pageLink{Page: c.titles[lk.name], Anchor: lk.fragment, Label: text})
		case lk.kind == linkGuide, lk.kind == linkRepo:
			replaceInline(n, &repoRef{Path: lk.repoPath})
		}
	}
	for _, n := range images {
		replaceInline(n, &repoRef{})
	}
	var buf bytes.Buffer
	_ = c.md.Renderer().Render(&buf, src, doc)
	out := buf.String()
	if ext := strings.TrimRight(c.opts.ExternalURL, "/"); ext != "" {
		// Code and link bodies were substituted raw (CDATA); everything
		// left is escaped markup.
		out = strings.ReplaceAll(out, Placeholder, html.EscapeString(ext))
	}
	if c.opts.Note != "" {
		out = `<ac:structured-macro ac:name="info"><ac:rich-text-body><p>` + html.EscapeString(c.opts.Note) +
			"</p></ac:rich-text-body></ac:structured-macro>\n" + out
	}
	return out
}

// pageLink is a link to a guide page (Page = its Confluence title) or, with
// an empty Page, to an anchor on the same page.
type pageLink struct {
	ast.BaseInline
	Page, Anchor, Label string
}

var kindPageLink = ast.NewNodeKind("ConfluencePageLink")

func (n *pageLink) Kind() ast.NodeKind { return kindPageLink }

func (n *pageLink) Dump(src []byte, level int) {
	ast.DumpHelper(n, src, level, map[string]string{"Page": n.Page, "Anchor": n.Anchor}, nil)
}

// cdata wraps s in a CDATA section; "]]>" inside s is split across two.
func cdata(s string) string {
	return "<![CDATA[" + strings.ReplaceAll(s, "]]>", "]]]]><![CDATA[>") + "]]>"
}

func attr(s string) string { return html.EscapeString(s) }

// codeLanguages maps a fence's info string to a language the Confluence
// Server/Data Center code macro knows; anything else is plain text.
var codeLanguages = map[string]string{
	"sh": "bash", "bash": "bash", "shell": "bash", "console": "bash", "zsh": "bash",
	"json": "js", "js": "js", "javascript": "js",
	"yaml": "yml", "yml": "yml",
	"xml": "xml", "html": "xml",
	"python": "py", "py": "py",
	"sql": "sql", "diff": "diff", "powershell": "powershell", "ps1": "powershell",
	"java": "java", "css": "css", "ruby": "ruby", "perl": "perl", "php": "php",
}

// codeLanguage is the code macro language for a fence's language.
func codeLanguage(fence string) string {
	if l, ok := codeLanguages[strings.ToLower(fence)]; ok {
		return l
	}
	return "text"
}

// storageRenderer overrides the HTML renderer for the nodes whose storage
// format differs from HTML.
type storageRenderer struct{ sub func(string) string }

func (r storageRenderer) RegisterFuncs(reg renderer.NodeRendererFuncRegisterer) {
	reg.Register(ast.KindHeading, renderHeading)
	reg.Register(ast.KindFencedCodeBlock, r.renderCode)
	reg.Register(ast.KindCodeBlock, r.renderCode)
	reg.Register(kindPageLink, renderPageLink)
	reg.Register(kindRepoRef, renderStorageRepoRef)
	reg.Register(east.KindTable, renderTable)
	reg.Register(east.KindTableHeader, renderTableRow)
	reg.Register(east.KindTableRow, renderTableRow)
	reg.Register(east.KindTableCell, renderTableCell)
	reg.Register(east.KindTaskCheckBox, renderTaskCheckBox)
}

// renderHeading writes <hN> without attributes and an anchor macro named by
// the GitHub slug that parse stored as the id attribute.
func renderHeading(w util.BufWriter, _ []byte, n ast.Node, entering bool) (ast.WalkStatus, error) {
	h := n.(*ast.Heading)
	tag := fmt.Sprintf("h%d", h.Level)
	if !entering {
		_, _ = w.WriteString("</" + tag + ">\n")
		return ast.WalkContinue, nil
	}
	_, _ = w.WriteString("<" + tag + ">")
	if id, ok := h.AttributeString("id"); ok {
		if b, ok := id.([]byte); ok && len(b) > 0 {
			_, _ = w.WriteString(`<ac:structured-macro ac:name="anchor"><ac:parameter ac:name="">` + attr(string(b)) +
				`</ac:parameter></ac:structured-macro>`)
		}
	}
	return ast.WalkContinue, nil
}

func (r storageRenderer) renderCode(w util.BufWriter, src []byte, n ast.Node, entering bool) (ast.WalkStatus, error) {
	if !entering {
		return ast.WalkContinue, nil
	}
	lang := "text"
	if f, ok := n.(*ast.FencedCodeBlock); ok {
		lang = codeLanguage(string(f.Language(src)))
	}
	var b strings.Builder
	lines := n.Lines()
	for i := 0; i < lines.Len(); i++ {
		seg := lines.At(i)
		b.Write(seg.Value(src))
	}
	code := strings.TrimRight(b.String(), "\n")
	if r.sub != nil {
		code = r.sub(code)
	}
	_, _ = w.WriteString(`<ac:structured-macro ac:name="code"><ac:parameter ac:name="language">` + lang +
		`</ac:parameter><ac:plain-text-body>` + cdata(code) + "</ac:plain-text-body></ac:structured-macro>\n")
	return ast.WalkSkipChildren, nil
}

func renderPageLink(w util.BufWriter, _ []byte, n ast.Node, entering bool) (ast.WalkStatus, error) {
	if !entering {
		return ast.WalkContinue, nil
	}
	l := n.(*pageLink)
	text := l.Label
	if text == "" {
		text = l.Page
	}
	_, _ = w.WriteString("<ac:link")
	if l.Anchor != "" {
		_, _ = w.WriteString(` ac:anchor="` + attr(l.Anchor) + `"`)
	}
	_, _ = w.WriteString(">")
	if l.Page != "" {
		_, _ = w.WriteString(`<ri:page ri:content-title="` + attr(l.Page) + `" />`)
	}
	_, _ = w.WriteString("<ac:plain-text-link-body>" + cdata(text) + "</ac:plain-text-link-body></ac:link>")
	return ast.WalkSkipChildren, nil
}

func renderStorageRepoRef(w util.BufWriter, _ []byte, n ast.Node, entering bool) (ast.WalkStatus, error) {
	if ref := n.(*repoRef); !entering && ref.Path != "" {
		_, _ = w.WriteString(" (in the repository: <code>" + html.EscapeString(ref.Path) + "</code>)")
	}
	return ast.WalkContinue, nil
}

// Tables use Confluence's own shape: one tbody, the header row with th.
func renderTable(w util.BufWriter, _ []byte, _ ast.Node, entering bool) (ast.WalkStatus, error) {
	if entering {
		_, _ = w.WriteString("<table><tbody>\n")
	} else {
		_, _ = w.WriteString("</tbody></table>\n")
	}
	return ast.WalkContinue, nil
}

func renderTableRow(w util.BufWriter, _ []byte, _ ast.Node, entering bool) (ast.WalkStatus, error) {
	if entering {
		_, _ = w.WriteString("<tr>")
	} else {
		_, _ = w.WriteString("</tr>\n")
	}
	return ast.WalkContinue, nil
}

func renderTableCell(w util.BufWriter, _ []byte, n ast.Node, entering bool) (ast.WalkStatus, error) {
	tag := "td"
	if n.Parent() != nil && n.Parent().Kind() == east.KindTableHeader {
		tag = "th"
	}
	if !entering {
		_, _ = w.WriteString("</" + tag + ">")
		return ast.WalkContinue, nil
	}
	style := ""
	switch n.(*east.TableCell).Alignment {
	case east.AlignLeft:
		style = ` style="text-align: left;"`
	case east.AlignRight:
		style = ` style="text-align: right;"`
	case east.AlignCenter:
		style = ` style="text-align: center;"`
	}
	_, _ = w.WriteString("<" + tag + style + ">")
	return ast.WalkContinue, nil
}

func renderTaskCheckBox(w util.BufWriter, _ []byte, n ast.Node, entering bool) (ast.WalkStatus, error) {
	if entering {
		if n.(*east.TaskCheckBox).IsChecked {
			_, _ = w.WriteString("[x] ")
		} else {
			_, _ = w.WriteString("[ ] ")
		}
	}
	return ast.WalkContinue, nil
}
