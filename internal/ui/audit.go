package ui

import (
	"net/http"
	"net/url"
	"strings"
	"time"

	"tls-broker/internal/auth"
	"tls-broker/internal/core"
)

const auditPageSize = 50

var auditTypes = []string{
	core.AuditGate, core.AuditOrder, core.AuditIssue, core.AuditDirectFetch, core.AuditDNSPresent, core.AuditDNSCleanup,
	core.AuditLogin, core.AuditLogout, core.AuditGrantChange, core.AuditUserChange, core.AuditConfigChange,
	core.AuditRateLimit, core.AuditProviderState, core.AuditFailover, core.AuditError,
}

type auditData struct {
	Events     []core.AuditEvent
	Type, Mode string
	Q          string
	Since      string // YYYY-MM-DD
	Until      string // YYYY-MM-DD
	PublicOnly bool
	CanAdmin   bool
	Types      []string
	Modes      []core.Mode
	Newer      bool   // the page is not the first one
	Older      string // query string of the next page; empty when none
}

func (h *Handler) auditPage(w http.ResponseWriter, r *http.Request, cur *auth.Current) {
	qv := r.URL.Query()
	d := &auditData{
		Type: qv.Get("type"), Mode: qv.Get("mode"), Q: strings.TrimSpace(qv.Get("q")),
		Since: qv.Get("since"), Until: qv.Get("until"),
		CanAdmin: cur.User.Can(core.RoleAdmin),
		Types:    auditTypes,
		Modes:    []core.Mode{core.ModeACME, core.ModeDirect, core.ModeDNSProxy, core.ModeUI},
	}
	d.PublicOnly = !d.CanAdmin || qv.Get("scope") == "public"
	query := core.AuditQuery{IncludeAdmin: !d.PublicOnly, Type: d.Type, Mode: core.Mode(d.Mode), Contains: d.Q, Limit: auditPageSize + 1}
	var msgs []string
	if t, err := time.Parse("2006-01-02", d.Since); err == nil {
		query.Since = t
	} else if d.Since != "" {
		msgs = append(msgs, "Ignored an invalid 'since' date.")
	}
	if t, err := time.Parse("2006-01-02", d.Until); err == nil {
		query.Until = t.AddDate(0, 0, 1) // the whole day
	} else if d.Until != "" {
		msgs = append(msgs, "Ignored an invalid 'until' date.")
	}
	// Paging by time: "before" is the time of the last event of the
	// previous page (exclusive upper bound).
	if b := qv.Get("before"); b != "" {
		if t, err := time.Parse(time.RFC3339Nano, b); err == nil && (query.Until.IsZero() || t.Before(query.Until)) {
			query.Until = t
			d.Newer = true
		}
	}
	if d.Type != "" && !contains(auditTypes, d.Type) {
		query.Type, d.Type = "", ""
	}
	events, err := h.Audit.Query(r.Context(), query)
	if err != nil {
		h.serverError(w, r, cur, "read audit log", err)
		return
	}
	if len(events) > auditPageSize {
		events = events[:auditPageSize]
		last := events[len(events)-1].Time
		v := url.Values{}
		for k, val := range map[string]string{"type": d.Type, "mode": d.Mode, "q": d.Q, "since": d.Since, "until": d.Until} {
			if val != "" {
				v.Set(k, val)
			}
		}
		if d.CanAdmin && d.PublicOnly {
			v.Set("scope", "public")
		}
		v.Set("before", last.UTC().Format(time.RFC3339Nano))
		d.Older = "?" + v.Encode()
	}
	d.Events = events
	p := h.newPage(w, r, cur, "Audit log", "audit", d)
	if len(msgs) > 0 {
		p.Flash = firstFlash(p.Flash, &flash{Kind: "warn", Text: strings.Join(msgs, " ")})
	}
	h.render(w, http.StatusOK, "audit", p)
}

func contains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}
