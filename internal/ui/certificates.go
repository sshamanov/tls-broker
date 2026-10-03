package ui

import (
	"context"
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
	Owner    ownerView
}

type directRow struct {
	core.DirectEntry
	Owner ownerView // of the active generation's certificate
}

// ownerView says who obtained a certificate: the owner of the grant that
// authorized its order. Kind is grant (User and Prefix set), deleted (the
// grant no longer exists), dns (authorized because the names resolved to
// the requester; no owner) or unknown (issued before owners were recorded).
type ownerView struct {
	Kind    string
	User    string
	Prefix  string
	GrantID int64
	IP      string
}

// ownerResolver resolves certificate owners from the live grants and users.
type ownerResolver struct {
	grants map[int64]core.Grant
	names  userNames
}

func (h *Handler) ownerResolver(ctx context.Context) (*ownerResolver, error) {
	grants, err := h.Grants.List(ctx, 0)
	if err != nil {
		return nil, err
	}
	names, err := h.userNames(ctx)
	if err != nil {
		return nil, err
	}
	o := &ownerResolver{grants: map[int64]core.Grant{}, names: names}
	for _, g := range grants {
		o.grants[g.ID] = g
	}
	return o, nil
}

func (o *ownerResolver) owner(c *core.Certificate) ownerView {
	v := ownerView{GrantID: c.GrantID}
	if c.SourceIP.IsValid() {
		v.IP = c.SourceIP.String()
	}
	switch g, ok := o.grants[c.GrantID]; {
	case c.GrantID == 0 && v.IP == "":
		v.Kind = "unknown"
	case c.GrantID == 0:
		v.Kind = "dns"
	case ok:
		v.Kind, v.User, v.Prefix = "grant", o.names.name(g.OwnerUserID), g.Prefix.String()
	default:
		v.Kind = "deleted"
	}
	return v
}

type certsData struct {
	Q, Provider, Mode string
	Expired           bool
	ACME              []certRow
	Direct            []directRow
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
	owners, err := h.ownerResolver(ctx)
	if err != nil {
		h.serverError(w, r, cur, "list grants", err)
		return
	}
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
			row := certRow{Certificate: c, Owner: owners.owner(&c)}
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
			row := directRow{DirectEntry: e, Owner: ownerView{Kind: "unknown"}}
			if e.CertificateID != "" {
				if c, err := h.Certs.Get(ctx, e.CertificateID); err == nil {
					row.Owner = owners.owner(c)
				} else if !isNotFound(err) {
					h.serverError(w, r, cur, "get certificate", err)
					return
				}
			}
			d.Direct = append(d.Direct, row)
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
