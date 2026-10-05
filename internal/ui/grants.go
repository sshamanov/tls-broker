package ui

import (
	"context"
	"fmt"
	"net/http"
	"net/netip"
	"net/url"
	"slices"
	"strings"

	"tls-broker/internal/auth"
	"tls-broker/internal/core"
)

const maxNote = 200

type grantsData struct {
	Rows        []grantRow
	Owners      []string // usernames that own a grant, for the filter
	Owner       string   // filter: "" (all), "mine" or a username
	CanWildcard bool
	CanRange    bool // may add grants wider than one address (admins)
	Form        grantForm
	Error       string
}

// grantRow is a grant with its owner's name and whether the viewer may
// change it (their own grant, or any grant for an admin). CanEnable is false
// for a non-admin's disabled grant wider than one address: they may disable
// or delete it, but only an admin may switch an address range back on.
type grantRow struct {
	core.Grant
	Owner     string
	Mine      bool
	CanEdit   bool
	CanEnable bool
}

// msgRangeAdminOnly answers a non-admin who adds a grant wider than a
// single address. The UI calls grants "addresses" and a grant wider than /32
// an "address range".
const msgRangeAdminOnly = "Only administrators can add an address range. Add a single address (10.1.2.3 or 10.1.2.3/32)."

// msgEnableRangeAdminOnly answers a non-admin who enables their own
// disabled grant wider than a single address.
const msgEnableRangeAdminOnly = "Only administrators can enable an address range. You can still delete it, or add a single address instead."

// minGrantBits is the widest prefix anyone may grant: /8. Anything wider is
// never a sensible LAN range and is refused for admins too.
const minGrantBits = 8

// singleAddress reports whether p covers exactly one IPv4 address.
func singleAddress(p netip.Prefix) bool { return p.Bits() == 32 }

type grantForm struct {
	Prefix, Note string
	Wildcard     bool
}

func (h *Handler) grantsPage(w http.ResponseWriter, r *http.Request, cur *auth.Current) {
	h.renderGrants(w, r, cur, http.StatusOK, grantForm{}, "")
}

// renderGrants lists every grant with its owner, filtered by the "owner"
// query parameter. A blocked user sees only their own grants, read-only.
func (h *Handler) renderGrants(w http.ResponseWriter, r *http.Request, cur *auth.Current, status int, form grantForm, errMsg string) {
	ctx := r.Context()
	var owner int64
	if cur.User.Blocked {
		owner = cur.User.ID
	}
	grants, err := h.Grants.List(ctx, owner)
	if err != nil {
		h.serverError(w, r, cur, "list grants", err)
		return
	}
	names, err := h.userNames(ctx)
	if err != nil {
		h.serverError(w, r, cur, "list users", err)
		return
	}
	admin := cur.User.Can(core.RoleAdmin)
	d := &grantsData{CanWildcard: cur.User.Can(core.RoleWildcardAllowed), CanRange: admin, Form: form, Error: errMsg}
	if !cur.User.Blocked {
		d.Owner = r.URL.Query().Get("owner")
	}
	seen := map[string]bool{}
	for _, g := range grants {
		row := grantRow{Grant: g, Owner: names.name(g.OwnerUserID), Mine: g.OwnerUserID == cur.User.ID}
		row.CanEdit = !cur.User.Blocked && (row.Mine || admin)
		row.CanEnable = row.CanEdit && (admin || singleAddress(g.Prefix))
		if !seen[row.Owner] {
			seen[row.Owner] = true
			d.Owners = append(d.Owners, row.Owner)
		}
		switch {
		case d.Owner == "" || d.Owner == "all":
		case d.Owner == "mine" && !row.Mine, d.Owner != "mine" && row.Owner != d.Owner:
			continue
		}
		d.Rows = append(d.Rows, row)
	}
	slices.Sort(d.Owners)
	h.render(w, status, "grants", h.newPage(w, r, cur, "Client access", "grants", d))
}

// userNames maps user IDs to usernames.
type userNames map[int64]string

func (h *Handler) userNames(ctx context.Context) (userNames, error) {
	users, err := h.Users.List(ctx)
	if err != nil {
		return nil, err
	}
	m := userNames{}
	for _, u := range users {
		m[u.ID] = u.Username
	}
	return m, nil
}

func (m userNames) name(id int64) string {
	if n, ok := m[id]; ok {
		return n
	}
	return fmt.Sprintf("user #%d", id)
}

// parseGrantPrefix accepts an IPv4 address (a /32) or an IPv4 CIDR from /8
// to /32. Whether the caller may add more than one address is checked
// separately.
func parseGrantPrefix(s string) (netip.Prefix, error) {
	s = strings.TrimSpace(s)
	var p netip.Prefix
	if strings.Contains(s, "/") {
		var err error
		if p, err = netip.ParsePrefix(s); err != nil {
			return p, fmt.Errorf("%q is not a valid IPv4 address.", s)
		}
	} else {
		a, err := netip.ParseAddr(s)
		if err != nil {
			return p, fmt.Errorf("%q is not a valid IPv4 address.", s)
		}
		p = netip.PrefixFrom(a, a.BitLen())
	}
	if !p.Addr().Is4() {
		return p, fmt.Errorf("%q is not IPv4; client access supports IPv4 addresses only.", s)
	}
	if p.Bits() < minGrantBits {
		return p, fmt.Errorf("A range wider than /%d is refused.", minGrantBits)
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
	if !singleAddress(prefix) && !cur.User.Can(core.RoleAdmin) {
		bad(http.StatusForbidden, msgRangeAdminOnly)
		return
	}
	if form.Wildcard && !cur.User.Can(core.RoleWildcardAllowed) {
		bad(http.StatusForbidden, "Your role may not allow wildcard certificates. Ask an administrator for the wildcard role.")
		return
	}
	g := &core.Grant{OwnerUserID: cur.User.ID, Prefix: prefix, Enabled: true, Wildcard: form.Wildcard, Note: form.Note, CreatedAt: h.Clock.Now()}
	if err := h.Grants.Create(r.Context(), g); err != nil {
		h.serverError(w, r, cur, "create grant", err)
		return
	}
	h.record(r, cur, core.AuditGrantChange, fmt.Sprintf("created grant %s wildcard=%t", g.Prefix, g.Wildcard), g.ID)
	h.redirect(w, r, base+"/grants", "ok", fmt.Sprintf("Added address %s. Machines there can request certificates now.", g.Prefix))
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
		if g.Enabled {
			return fmt.Sprintf("Enabled address %s.", g.Prefix), nil
		}
		return fmt.Sprintf("Disabled address %s. Machines there can no longer request certificates through it.", g.Prefix), nil
	case "delete":
		if err := h.Grants.Delete(r.Context(), g.ID); err != nil {
			return "", err
		}
		h.record(r, cur, core.AuditGrantChange, fmt.Sprintf("deleted grant %s wildcard=%t", g.Prefix, g.Wildcard), g.ID)
		return fmt.Sprintf("Deleted address %s.", g.Prefix), nil
	}
	return "", errUnknownAction
}

var errUnknownAction = fmt.Errorf("unknown action")

// grantAction enables, disables or deletes a grant. Users change their own
// grants; admins change any. Someone else's grant answers 403: every user
// sees all grants, so its existence is no secret. Only an admin may enable a
// grant wider than one address; its non-admin owner may still disable or
// delete it.
func (h *Handler) grantAction(w http.ResponseWriter, r *http.Request, cur *auth.Current) {
	if !limitForm(w, r, maxForm) {
		return
	}
	back := base + "/grants"
	if o := r.PostFormValue("owner"); o != "" {
		back += "?owner=" + url.QueryEscape(o)
	}
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
	if g.OwnerUserID != cur.User.ID && !cur.User.Can(core.RoleAdmin) {
		h.forbidden(w, r, cur)
		return
	}
	action := r.PathValue("action")
	if action == "enable" && !singleAddress(g.Prefix) && !cur.User.Can(core.RoleAdmin) {
		h.renderGrants(w, r, cur, http.StatusForbidden, grantForm{}, msgEnableRangeAdminOnly)
		return
	}
	msg, err := h.applyGrantAction(r, cur, g, action)
	switch {
	case err == errUnknownAction:
		h.notFound(w, r, cur)
	case isNotFound(err):
		h.redirect(w, r, back, "error", "That address was already removed.")
	case err != nil:
		h.serverError(w, r, cur, "change grant", err)
	default:
		h.redirect(w, r, back, "ok", msg)
	}
}
