package ui

import (
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"tls-broker/internal/auth"
	"tls-broker/internal/core"
)

const certPageSize = 50

type certRow struct {
	core.Certificate
	Interval time.Duration // lineage observed interval; 0 when unknown
}

type certsData struct {
	Q, Provider, Mode string
	Expired           bool
	ACME              []certRow
	Direct            []core.DirectEntry
	Providers         []string
	Offset            int
	Prev, Next        string // query strings for paging, empty when none
	CanRotate         bool
}

func (h *Handler) certificates(w http.ResponseWriter, r *http.Request, cur *auth.Current) {
	q := r.URL.Query()
	d := &certsData{
		Q:         strings.ToLower(strings.TrimSpace(q.Get("q"))),
		Provider:  q.Get("provider"),
		Mode:      q.Get("mode"),
		Expired:   q.Get("expired") == "1",
		CanRotate: h.Rotator != nil && cur.User.Can(core.RoleAdmin),
	}
	if d.Mode != "acme" && d.Mode != "direct" {
		d.Mode = ""
	}
	d.Offset, _ = strconv.Atoi(q.Get("offset"))
	d.Offset = max(d.Offset, 0)
	ctx := r.Context()
	now := h.Clock.Now()
	for _, p := range h.Config.Current().Providers {
		d.Providers = append(d.Providers, p.Name)
	}

	if d.Mode != "direct" {
		f := core.CertificateFilter{Mode: core.ModeACME, Provider: d.Provider, NameContains: d.Q, Limit: certPageSize + 1, Offset: d.Offset}
		if !d.Expired {
			f.ValidAt = now
		}
		certs, err := h.Certs.List(ctx, f)
		if err != nil {
			h.serverError(w, r, cur, "list certificates", err)
			return
		}
		more := len(certs) > certPageSize
		if more {
			certs = certs[:certPageSize]
		}
		for _, c := range certs {
			row := certRow{Certificate: c}
			if l, err := h.Lineages.Get(ctx, c.Names.Key()); err == nil && l.Samples > 0 {
				row.Interval = l.ObservedInterval
			}
			d.ACME = append(d.ACME, row)
		}
		if more {
			d.Next = d.pageQuery(d.Offset + certPageSize)
		}
		if d.Offset > 0 {
			d.Prev = d.pageQuery(max(d.Offset-certPageSize, 0))
		}
	}
	if d.Mode != "acme" {
		entries, err := h.Direct.List(ctx)
		if err != nil {
			h.serverError(w, r, cur, "list direct entries", err)
			return
		}
		needle := strings.ToLower(d.Q)
		for _, e := range entries {
			if needle != "" && !strings.Contains(strings.ToLower(e.Identifier), needle) {
				continue
			}
			if d.Provider != "" && e.Provider != d.Provider {
				continue
			}
			if !d.Expired && !e.NotAfter.IsZero() && !e.NotAfter.After(now) {
				continue
			}
			d.Direct = append(d.Direct, e)
		}
	}
	h.render(w, http.StatusOK, "certificates", h.newPage(w, r, cur, "Certificates", "certificates", d))
}

func (d *certsData) pageQuery(offset int) string {
	v := url.Values{}
	if d.Q != "" {
		v.Set("q", d.Q)
	}
	if d.Provider != "" {
		v.Set("provider", d.Provider)
	}
	if d.Mode != "" {
		v.Set("mode", d.Mode)
	}
	if d.Expired {
		v.Set("expired", "1")
	}
	if offset > 0 {
		v.Set("offset", strconv.Itoa(offset))
	}
	return "?" + v.Encode()
}

// rotateKey is the hook for direct-mode key rotation. It is available only
// once a KeyRotator is wired in.
func (h *Handler) rotateKey(w http.ResponseWriter, r *http.Request, cur *auth.Current) {
	if h.Rotator == nil {
		h.notFound(w, r, cur)
		return
	}
	if !limitForm(w, r, maxForm) {
		return
	}
	id := strings.TrimSpace(r.PostFormValue("identifier"))
	if _, err := h.Direct.Get(r.Context(), id); err != nil {
		if isNotFound(err) {
			h.notFound(w, r, cur)
		} else {
			h.serverError(w, r, cur, "get direct entry", err)
		}
		return
	}
	if err := h.Rotator.Rotate(r.Context(), id); err != nil {
		h.Logger.Warn("ui: key rotation failed", "identifier", id, "error", err)
		h.redirect(w, r, base+"/certificates?mode=direct", "error", "Key rotation for "+id+" failed; see the activity log and the server log.")
		return
	}
	h.record(r, cur, core.AuditConfigChange, "rotated direct key of "+id, 0)
	h.redirect(w, r, base+"/certificates?mode=direct", "ok", "Key of "+id+" rotated.")
}
