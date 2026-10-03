package ui

import (
	"fmt"
	"net/http"
	"net/netip"
	"strings"

	"tls-broker/internal/auth"
	"tls-broker/internal/core"
)

const maxNote = 200

type grantsData struct {
	Grants      []core.Grant
	CanWildcard bool
	Form        grantForm
	Error       string
}

type grantForm struct {
	Prefix, Note string
	Wildcard     bool
}

func (h *Handler) grantsPage(w http.ResponseWriter, r *http.Request, cur *auth.Current) {
	h.renderGrants(w, r, cur, http.StatusOK, grantForm{}, "")
}

func (h *Handler) renderGrants(w http.ResponseWriter, r *http.Request, cur *auth.Current, status int, form grantForm, errMsg string) {
	grants, err := h.Grants.List(r.Context(), cur.User.ID)
	if err != nil {
		h.serverError(w, r, cur, "list grants", err)
		return
	}
	d := &grantsData{Grants: grants, CanWildcard: cur.User.Can(core.RoleWildcardAllowed), Form: form, Error: errMsg}
	h.render(w, status, "grants", h.newPage(w, r, cur, "My grants", "grants", d))
}

// parseGrantPrefix accepts an IPv4 address (a /32) or an IPv4 CIDR.
func parseGrantPrefix(s string) (netip.Prefix, error) {
	s = strings.TrimSpace(s)
	var p netip.Prefix
	if strings.Contains(s, "/") {
		var err error
		if p, err = netip.ParsePrefix(s); err != nil {
			return p, fmt.Errorf("%q is not a valid IPv4 address or CIDR", s)
		}
	} else {
		a, err := netip.ParseAddr(s)
		if err != nil {
			return p, fmt.Errorf("%q is not a valid IPv4 address or CIDR", s)
		}
		p = netip.PrefixFrom(a, a.BitLen())
	}
	if !p.Addr().Is4() {
		return p, fmt.Errorf("%q is not IPv4; grants support IPv4 only", s)
	}
	if p.Bits() == 0 {
		return p, fmt.Errorf("a /0 grant would cover every address and is refused")
	}
	return p.Masked(), nil
}

func (h *Handler) grantCreate(w http.ResponseWriter, r *http.Request, cur *auth.Current) {
	r.Body = http.MaxBytesReader(w, r.Body, 64<<10)
	form := grantForm{
		Prefix:   strings.TrimSpace(r.PostFormValue("prefix")),
		Note:     strings.TrimSpace(r.PostFormValue("note")),
		Wildcard: r.PostFormValue("wildcard") == "true",
	}
	bad := func(status int, msg string) {
		h.renderGrants(w, r, cur, status, form, msg)
	}
	prefix, err := parseGrantPrefix(form.Prefix)
	if err != nil {
		bad(http.StatusBadRequest, err.Error())
		return
	}
	if len(form.Note) > maxNote {
		bad(http.StatusBadRequest, fmt.Sprintf("The note is longer than %d characters.", maxNote))
		return
	}
	if form.Wildcard && !cur.User.Can(core.RoleWildcardAllowed) {
		bad(http.StatusForbidden, "Your role may not create wildcard grants.")
		return
	}
	g := &core.Grant{OwnerUserID: cur.User.ID, Prefix: prefix, Enabled: true, Wildcard: form.Wildcard, Note: form.Note, CreatedAt: h.Clock.Now()}
	if err := h.Grants.Create(r.Context(), g); err != nil {
		h.serverError(w, r, cur, "create grant", err)
		return
	}
	h.record(r, cur, core.AuditGrantChange, fmt.Sprintf("created grant %s wildcard=%t", g.Prefix, g.Wildcard), g.ID)
	h.redirect(w, r, base+"/grants", "ok", fmt.Sprintf("Grant %s created.", g.Prefix))
}

// applyGrantAction performs enable, disable or delete on grant id. The caller
// has already decided the user may touch it.
func (h *Handler) applyGrantAction(r *http.Request, cur *auth.Current, g *core.Grant, action string) (string, error) {
	switch action {
	case "enable", "disable":
		g.Enabled = action == "enable"
		if err := h.Grants.Update(r.Context(), g); err != nil {
			return "", err
		}
		h.record(r, cur, core.AuditGrantChange, fmt.Sprintf("%sd grant %s", action, g.Prefix), g.ID)
		return fmt.Sprintf("Grant %s %sd.", g.Prefix, action), nil
	case "delete":
		if err := h.Grants.Delete(r.Context(), g.ID); err != nil {
			return "", err
		}
		h.record(r, cur, core.AuditGrantChange, fmt.Sprintf("deleted grant %s wildcard=%t", g.Prefix, g.Wildcard), g.ID)
		return fmt.Sprintf("Grant %s deleted.", g.Prefix), nil
	}
	return "", errUnknownAction
}

var errUnknownAction = fmt.Errorf("unknown action")

func (h *Handler) grantAction(w http.ResponseWriter, r *http.Request, cur *auth.Current) {
	h.doGrantAction(w, r, cur, base+"/grants", false)
}

func (h *Handler) adminGrantAction(w http.ResponseWriter, r *http.Request, cur *auth.Current) {
	h.doGrantAction(w, r, cur, base+"/admin/grants", true)
}

func (h *Handler) doGrantAction(w http.ResponseWriter, r *http.Request, cur *auth.Current, back string, anyOwner bool) {
	id, ok := formInt(r, "id")
	if !ok {
		h.notFound(w, r, cur)
		return
	}
	g, err := h.Grants.Get(r.Context(), id)
	if err != nil {
		if isNotFound(err) {
			h.notFound(w, r, cur)
		} else {
			h.serverError(w, r, cur, "get grant", err)
		}
		return
	}
	// Someone else's grant looks like it does not exist.
	if !anyOwner && g.OwnerUserID != cur.User.ID {
		h.notFound(w, r, cur)
		return
	}
	msg, err := h.applyGrantAction(r, cur, g, r.PathValue("action"))
	switch {
	case err == errUnknownAction:
		h.notFound(w, r, cur)
	case isNotFound(err):
		h.redirect(w, r, back, "error", "That grant no longer exists.")
	case err != nil:
		h.serverError(w, r, cur, "change grant", err)
	default:
		h.redirect(w, r, back, "ok", msg)
	}
}

type adminGrantRow struct {
	core.Grant
	Owner string
}

type adminGrantsData struct{ Rows []adminGrantRow }

func (h *Handler) adminGrants(w http.ResponseWriter, r *http.Request, cur *auth.Current) {
	grants, err := h.Grants.List(r.Context(), 0)
	if err != nil {
		h.serverError(w, r, cur, "list grants", err)
		return
	}
	users, err := h.Users.List(r.Context())
	if err != nil {
		h.serverError(w, r, cur, "list users", err)
		return
	}
	owners := map[int64]string{}
	for _, u := range users {
		owners[u.ID] = u.Username
	}
	d := &adminGrantsData{}
	for _, g := range grants {
		o := owners[g.OwnerUserID]
		if o == "" {
			o = fmt.Sprintf("user #%d", g.OwnerUserID)
		}
		d.Rows = append(d.Rows, adminGrantRow{Grant: g, Owner: o})
	}
	h.render(w, http.StatusOK, "admin_grants", h.newPage(w, r, cur, "All grants", "admin-grants", d))
}
