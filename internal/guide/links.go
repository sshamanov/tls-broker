package guide

import (
	"net/url"
	"path"
	"strings"

	"github.com/yuin/goldmark/ast"
)

type linkKind int

const (
	// linkAnchor: "#section", a heading of the guide itself.
	linkAnchor linkKind = iota
	// linkExternal: an absolute URL (any scheme) or a protocol-relative one.
	linkExternal
	// linkRepo: any relative path; it resolves inside the repository only
	// and is served neither by the reader nor in Confluence.
	linkRepo
)

type link struct {
	kind     linkKind
	repoPath string // linkRepo: path from the repository root
	fragment string // without "#"
}

// guideDir is the repository directory that holds File; relative links in
// the guide resolve against it.
const guideDir = "docs"

// classify sorts a link destination as written in the guide.
func classify(dest string) link {
	if strings.HasPrefix(dest, "#") {
		return link{kind: linkAnchor, fragment: dest[1:]}
	}
	u, err := url.Parse(dest)
	if err != nil || u.Scheme != "" || u.Host != "" || strings.HasPrefix(dest, "//") {
		return link{kind: linkExternal}
	}
	return link{kind: linkRepo, fragment: u.Fragment, repoPath: path.Join(guideDir, u.Path)}
}

// contentsSection returns the guide's table of contents: the level-2
// heading titled ContentsTitle and the blocks after it up to the next
// heading. It returns nil when there is none.
func contentsSection(doc ast.Node, src []byte) (heading ast.Node, blocks []ast.Node) {
	for n := doc.FirstChild(); n != nil; n = n.NextSibling() {
		h, ok := n.(*ast.Heading)
		if !ok || h.Level != 2 || plainText(h, src) != ContentsTitle {
			continue
		}
		for b := n.NextSibling(); b != nil; b = b.NextSibling() {
			if b.Kind() == ast.KindHeading {
				break
			}
			blocks = append(blocks, b)
		}
		return n, blocks
	}
	return nil, nil
}

// headingID is the ID parse gave a heading.
func headingID(n ast.Node) string {
	if id, ok := n.AttributeString("id"); ok {
		if b, ok := id.([]byte); ok {
			return string(b)
		}
	}
	return ""
}
