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
	HTML        template.HTML
	TOC         []guide.Heading
}

// docs serves the user guide, one document (GET /ui/docs); its level-2 and
// level-3 headings are the navigation.
func (h *Handler) docs(w http.ResponseWriter, r *http.Request, cur *auth.Current) {
	ext := ""
	if cfg := h.Config.Current(); cfg != nil {
		ext = cfg.Server.ExternalURL
	}
	p, err := h.guide.Document(ext)
	switch {
	case errors.Is(err, guide.ErrUnavailable):
		h.render(w, http.StatusOK, "docs", h.newPage(w, r, cur, "Documentation", "docs", docsView{Unavailable: true}))
		return
	case err != nil:
		h.serverError(w, r, cur, "documentation", err)
		return
	}
	v := docsView{
		// The guide renders Markdown with raw HTML disabled; see
		// internal/guide.
		HTML: template.HTML(p.HTML),
		TOC:  p.TOC,
	}
	h.render(w, http.StatusOK, "docs", h.newPage(w, r, cur, p.Title, "docs", v))
}

// docsMoved redirects the pages the guide used to be split into
// (GET /ui/docs/{page}) to their section of the one document, so old links
// and bookmarks keep working; any other name is the 404 page. The name is
// only looked up, never used as a path.
func (h *Handler) docsMoved(w http.ResponseWriter, r *http.Request, cur *auth.Current) {
	id, ok := guide.MovedPages[r.PathValue("page")]
	if !ok {
		h.notFound(w, r, cur)
		return
	}
	http.Redirect(w, r, guide.Base+"#"+id, http.StatusMovedPermanently)
}
