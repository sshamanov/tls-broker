package ui

import (
	"errors"
	"html/template"
	"net/http"

	"tls-broker/internal/auth"
	"tls-broker/internal/guide"
)

// docsView is the data of the documentation reader.
type docsView struct {
	Unavailable bool
	Index       guide.Index
	Current     string // page name, "" for the index page
	HTML        template.HTML
	TOC         []guide.Heading
}

// docsIndex serves the guide's index page (GET /ui/docs).
func (h *Handler) docsIndex(w http.ResponseWriter, r *http.Request, cur *auth.Current) {
	h.docs(w, r, cur, "")
}

// docsPage serves one page the index lists (GET /ui/docs/{page}); anything
// else is the 404 page. The name is one decoded path segment ("../plan" is
// possible) and must be a listed page name, so it never reaches a file
// outside the guide; there is no directory listing.
func (h *Handler) docsPage(w http.ResponseWriter, r *http.Request, cur *auth.Current) {
	h.docs(w, r, cur, r.PathValue("page"))
}

func (h *Handler) docs(w http.ResponseWriter, r *http.Request, cur *auth.Current, name string) {
	ext := ""
	if cfg := h.Config.Current(); cfg != nil {
		ext = cfg.Server.ExternalURL
	}
	p, err := h.guide.Page(name, ext)
	switch {
	case errors.Is(err, guide.ErrUnavailable):
		h.render(w, http.StatusOK, "docs", h.newPage(w, r, cur, "Documentation", "docs", docsView{Unavailable: true}))
		return
	case errors.Is(err, guide.ErrNotFound):
		h.notFound(w, r, cur)
		return
	case err != nil:
		h.serverError(w, r, cur, "documentation", err)
		return
	}
	idx, err := h.guide.Index()
	if err != nil {
		h.serverError(w, r, cur, "documentation", err)
		return
	}
	v := docsView{
		Index:   idx,
		Current: name,
		// The guide renders Markdown with raw HTML disabled; see
		// internal/guide.
		HTML: template.HTML(p.HTML),
	}
	if name != "" {
		// The index page's sections are the navigation already.
		v.TOC = p.TOC
	}
	h.render(w, http.StatusOK, "docs", h.newPage(w, r, cur, p.Title, "docs", v))
}
