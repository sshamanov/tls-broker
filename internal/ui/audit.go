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

// auditTypes are every event type, in the admin's type filter.
var auditTypes = []string{
	core.AuditGate, core.AuditOrder, core.AuditIssue, core.AuditDirectFetch, core.AuditDNSPresent, core.AuditDNSCleanup,
	core.AuditLogin, core.AuditLogout, core.AuditGrantChange, core.AuditUserChange, core.AuditConfigChange,
	core.AuditProviderState, core.AuditFailover, core.AuditError,
}

// activityTypes is the allow-list of event types users who are not admins
// see: issuance requests and their outcome (gate decisions including
// denials, orders admitted or refused, certificates issued or failed), DNS
// proxy publications, and grant changes. Logins, user, config and secret
// changes, provider state, failover, errors, DNS cleanups and direct-mode
// fetches stay with admins. Those users never see Detail either (it can carry
// resolver, upstream or internal error text): they get activitySummary.
var activityTypes = []string{core.AuditGate, core.AuditOrder, core.AuditIssue, core.AuditDNSPresent, core.AuditGrantChange}

type auditData struct {
	Events     []core.AuditEvent
	Type, Mode string
	Q          string
	Since      string // YYYY-MM-DD
	Until      string // YYYY-MM-DD
	CanAdmin   bool
	Types      []string
	Modes      []core.Mode
	Newer      bool   // the page is not the first one
	Older      string // query string of the next page; empty when none
}

// activityQuery restricts q to what the viewer may see.
func activityQuery(q core.AuditQuery, admin bool) core.AuditQuery {
	if !admin {
		q.Types, q.SkipDetail = activityTypes, true
	}
	return q
}

func (h *Handler) auditPage(w http.ResponseWriter, r *http.Request, cur *auth.Current) {
	qv := r.URL.Query()
	d := &auditData{
		Type: qv.Get("type"), Mode: qv.Get("mode"), Q: strings.TrimSpace(qv.Get("q")),
		Since: qv.Get("since"), Until: qv.Get("until"),
		CanAdmin: cur.User.Can(core.RoleAdmin),
		Types:    activityTypes,
		Modes:    []core.Mode{core.ModeACME, core.ModeDirect, core.ModeDNSProxy, core.ModeUI},
	}
	if d.CanAdmin {
		d.Types = auditTypes
	}
	query := activityQuery(core.AuditQuery{Type: d.Type, Mode: core.Mode(d.Mode), Contains: d.Q, Limit: auditPageSize + 1}, d.CanAdmin)
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
	if d.Type != "" && !contains(d.Types, d.Type) {
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
		v.Set("before", last.UTC().Format(time.RFC3339Nano))
		d.Older = "?" + v.Encode()
	}
	d.Events = events
	p := h.newPage(w, r, cur, "Activity log", "audit", d)
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

// reasonText says a decision reason in words.
var reasonText = map[string]string{
	core.ReasonDNSIPMatch:            "the names resolve to the requester",
	core.ReasonIPGrant:               "an IP grant covers the requester",
	core.ReasonWildcardGrantRequired: "a wildcard needs a wildcard grant",
	core.ReasonWildcardUnprotected:   "the zone's CAA records do not protect wildcards",
	core.ReasonDNSMismatch:           "a name does not resolve to the requesting address",
	core.ReasonDNSFailure:            "the DNS lookup failed; retry later",
	core.ReasonOutsideManagedZone:    "a name is outside the managed zones",
	core.ReasonInvalidIdentifier:     "a name is not valid",
	core.ReasonNotIPv4:               "the requester is not an IPv4 address",
	core.ReasonBlocked:               "the account is blocked",
	core.ReasonRateLimited:           "a certificate authority rate limit is reached",
	core.ReasonProviderUnavailable:   "no certificate authority is available",
}

func reasonWords(reason string) string {
	if t, ok := reasonText[reason]; ok {
		return t
	}
	return reason
}

// outcome is the event's result in one word: ok, denied or failed.
func outcome(ev core.AuditEvent) string {
	switch {
	case ev.Result != "":
		return ev.Result
	case ev.Decision == core.AuditDecisionDeny:
		return core.AuditResultDenied
	case ev.Decision == core.AuditDecisionAllow:
		return core.AuditResultOK
	}
	return ""
}

// activitySummary says what happened in one sentence, from the event's type,
// outcome and reason only (never Detail, except for grant changes, whose
// detail the UI writes itself: "created grant 10.0.0.0/24 wildcard=false").
func activitySummary(ev core.AuditEvent) string {
	why := func(prefix string) string {
		if ev.Reason == "" {
			return prefix + "."
		}
		return prefix + ": " + reasonWords(ev.Reason) + "."
	}
	out := outcome(ev)
	switch ev.Type {
	case core.AuditGate:
		if out == core.AuditResultOK {
			return why("Request allowed")
		}
		if out == core.AuditResultFailed {
			return "Request not decided: authorization failed; retry later."
		}
		return why("Request denied")
	case core.AuditOrder:
		switch out {
		case core.AuditResultOK:
			if ev.Provider != "" {
				return "Order admitted at " + ev.Provider + "."
			}
			return "Order admitted."
		case core.AuditResultDenied:
			return why("Order refused")
		}
		return "Order ended without a certificate."
	case core.AuditIssue:
		if out == core.AuditResultOK {
			s := "Certificate issued"
			if ev.Provider != "" {
				s += " by " + ev.Provider
			}
			if ev.CertNotAfter != nil {
				s += ", valid until " + ev.CertNotAfter.UTC().Format("2006-01-02")
			}
			return s + "."
		}
		return why("Issuance failed")
	case core.AuditDNSPresent:
		switch out {
		case core.AuditResultOK:
			return "DNS-01 value published."
		case core.AuditResultDenied:
			return why("DNS-01 publication denied")
		}
		return "DNS-01 publication failed."
	case core.AuditGrantChange:
		if ev.Detail == "" {
			return "Grant changed."
		}
		d := strings.Replace(ev.Detail, " wildcard=true", " (wildcards allowed)", 1)
		d = strings.Replace(d, " wildcard=false", "", 1)
		return strings.ToUpper(d[:1]) + d[1:] + "."
	}
	return ev.Type
}
