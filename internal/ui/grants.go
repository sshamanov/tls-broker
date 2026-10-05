package ui

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/netip"
	"net/url"
	"slices"
	"strings"
	"unicode"

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
	Refused     []grantRefusal // entries of the Add address field, when several were sent
}

// grantRow is a grant with its owner's name and whether the viewer may
// change it (their own grant, or any grant for an admin). CanEnable is false
// for a non-admin's disabled grant wider than one address: they may disable
// or delete it, but only an admin may switch an address range back on.
// CanEdit (note and wildcard) follows the same rule: a non-admin edits only
// their own single addresses.
type grantRow struct {
	core.Grant
	Owner     string
	Mine      bool
	CanManage bool
	CanEnable bool
	CanEdit   bool
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
func (h *Handler) renderGrants(w http.ResponseWriter, r *http.Request, cur *auth.Current, status int, form grantForm, errMsg string, refused ...grantRefusal) {
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
	d := &grantsData{CanWildcard: cur.User.Can(core.RoleWildcardAllowed), CanRange: admin, Form: form, Error: errMsg, Refused: refused}
	if !cur.User.Blocked {
		d.Owner = r.URL.Query().Get("owner")
	}
	seen := map[string]bool{}
	for _, g := range grants {
		row := grantRow{Grant: g, Owner: names.name(g.OwnerUserID), Mine: g.OwnerUserID == cur.User.ID}
		row.CanManage = !cur.User.Blocked && (row.Mine || admin)
		row.CanEnable = row.CanManage && (admin || singleAddress(g.Prefix))
		row.CanEdit = row.CanEnable
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

// maxGrantEntries caps how many addresses one submit of the Add address
// form may carry.
const maxGrantEntries = 50

// parseGrantPrefix accepts an IPv4 address (a /32) or an IPv4 CIDR from /8
// to /32. Whether the caller may add more than one address is checked
// separately. The error is a sentence for the user that does not repeat
// the entry.
func parseGrantPrefix(s string) (netip.Prefix, error) {
	s = strings.TrimSpace(s)
	var p netip.Prefix
	if strings.Contains(s, "/") {
		var err error
		if p, err = netip.ParsePrefix(s); err != nil {
			return p, errors.New("Not a valid IPv4 address.")
		}
	} else {
		a, err := netip.ParseAddr(s)
		if err != nil {
			return p, errors.New("Not a valid IPv4 address.")
		}
		p = netip.PrefixFrom(a, a.BitLen())
	}
	if !p.Addr().Is4() {
		return p, errors.New("Not IPv4; client access takes IPv4 addresses only.")
	}
	if p.Bits() < minGrantBits {
		return p, fmt.Errorf("A range wider than /%d is refused.", minGrantBits)
	}
	return p.Masked(), nil
}

// splitGrantEntries splits the Add address field on commas and whitespace.
func splitGrantEntries(s string) []string {
	return strings.FieldsFunc(s, func(r rune) bool { return r == ',' || unicode.IsSpace(r) })
}

// grantRefusal is one entry of the Add address field that was refused.
type grantRefusal struct{ Entry, Reason string }

// listPrefixes joins prefixes for a flash, naming at most ten.
func listPrefixes(ps []netip.Prefix) string {
	var parts []string
	for i, p := range ps {
		if i == 10 {
			return strings.Join(parts, ", ") + fmt.Sprintf(" and %d more", len(ps)-10)
		}
		parts = append(parts, p.String())
	}
	return strings.Join(parts, ", ")
}

// grantCreate adds the addresses in the form's prefix field, separated by
// commas or whitespace. Every entry is checked with the caller's rules
// before anything is stored: one refused entry stores nothing and the form
// lists what was refused and why. Duplicates within the input collapse; an
// entry the caller already owns is skipped and named in the flash, which
// points to Edit (adding again never changes the existing grant). Someone
// else's grant for the same prefix does not count: grants are per owner. The
// note and the wildcard choice apply to every new grant, each audited on its
// own.
func (h *Handler) grantCreate(w http.ResponseWriter, r *http.Request, cur *auth.Current) {
	r.Body = http.MaxBytesReader(w, r.Body, 64<<10)
	form := grantForm{
		Prefix:   strings.TrimSpace(r.PostFormValue("prefix")),
		Note:     strings.TrimSpace(r.PostFormValue("note")),
		Wildcard: r.PostFormValue("wildcard") == "true",
	}
	bad := func(status int, msg string, refused []grantRefusal) {
		h.renderGrants(w, r, cur, status, form, msg, refused...)
	}
	entries := splitGrantEntries(form.Prefix)
	switch {
	case len(entries) == 0:
		bad(http.StatusBadRequest, "Enter an IPv4 address.", nil)
		return
	case len(entries) > maxGrantEntries:
		bad(http.StatusBadRequest, fmt.Sprintf("Enter at most %d addresses at a time; this has %d.", maxGrantEntries, len(entries)), nil)
		return
	}
	if len(form.Note) > maxNote {
		bad(http.StatusBadRequest, fmt.Sprintf("The note is longer than %d characters.", maxNote), nil)
		return
	}
	if form.Wildcard && !cur.User.Can(core.RoleWildcardAllowed) {
		bad(http.StatusForbidden, "Your role may not allow wildcard certificates. Ask an administrator for the wildcard role.", nil)
		return
	}
	admin := cur.User.Can(core.RoleAdmin)
	var (
		prefixes []netip.Prefix
		refused  []grantRefusal
		status   = http.StatusForbidden
		seen     = map[netip.Prefix]bool{}
	)
	for _, e := range entries {
		p, err := parseGrantPrefix(e)
		switch {
		case err != nil:
			refused = append(refused, grantRefusal{e, err.Error()})
			status = http.StatusBadRequest
		case !singleAddress(p) && !admin:
			refused = append(refused, grantRefusal{e, msgRangeAdminOnly})
		case !seen[p]:
			seen[p] = true
			prefixes = append(prefixes, p)
		}
	}
	if len(refused) > 0 {
		if len(entries) == 1 {
			bad(status, refused[0].Reason, nil)
		} else {
			bad(status, fmt.Sprintf("Nothing was added: %d of %d entries were refused.", len(refused), len(entries)), refused)
		}
		return
	}
	own, err := h.Grants.List(r.Context(), cur.User.ID)
	if err != nil {
		h.serverError(w, r, cur, "list grants", err)
		return
	}
	for _, g := range own {
		delete(seen, g.Prefix)
	}
	var added, skipped []netip.Prefix
	for _, p := range prefixes {
		if !seen[p] {
			skipped = append(skipped, p)
			continue
		}
		g := &core.Grant{OwnerUserID: cur.User.ID, Prefix: p, Enabled: true, Wildcard: form.Wildcard, Note: form.Note, CreatedAt: h.Clock.Now()}
		if err := h.Grants.Create(r.Context(), g); err != nil {
			h.serverError(w, r, cur, "create grant", err)
			return
		}
		h.record(r, cur, core.AuditGrantChange, fmt.Sprintf("created grant %s wildcard=%t", g.Prefix, g.Wildcard), g.ID)
		added = append(added, p)
	}
	var msg string
	switch len(added) {
	case 0:
	case 1:
		msg = fmt.Sprintf("Added address %s. Machines there can request certificates now.", added[0])
	default:
		msg = fmt.Sprintf("Added %d addresses: %s. Machines there can request certificates now.", len(added), listPrefixes(added))
	}
	kind := "ok"
	if len(skipped) > 0 {
		if msg == "" {
			msg = "Nothing was added."
			kind = "warn"
		}
		msg += " " + skippedSentence(skipped)
	}
	h.redirect(w, r, base+"/grants", kind, msg)
}

// skippedSentence names the addresses an add skipped because the user
// already has them, and says how to change those instead.
func skippedSentence(ps []netip.Prefix) string {
	if len(ps) == 1 {
		return ps[0].String() + " is already listed as yours; use Edit on its row to change it."
	}
	return listPrefixes(ps) + " are already listed as yours; use Edit on their rows to change them."
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

// msgEditRangeAdminOnly answers a non-admin who edits their own grant wider
// than a single address.
const msgEditRangeAdminOnly = "Only administrators can edit an address range. You can still disable or delete it."

// grantEditData is the Edit address page: the note and, for users with the
// wildcard role, the wildcard switch. The address itself is fixed.
type grantEditData struct {
	Grant       core.Grant
	Owner       string // the grant owner's username
	Mine        bool
	CanWildcard bool
	Note        string
	Wildcard    bool
	Filter      string // the list's owner filter, kept for the way back
	Error       string
}

// editableGrant loads grant {id} for editing and answers 404, 403 or a
// server error itself when it may not be edited by cur: users edit their
// own single addresses, admins any grant.
func (h *Handler) editableGrant(w http.ResponseWriter, r *http.Request, cur *auth.Current) (*core.Grant, bool) {
	id, ok := formInt(r, "id")
	if !ok {
		h.notFound(w, r, cur)
		return nil, false
	}
	g, err := h.Grants.Get(r.Context(), id)
	if err != nil {
		if isNotFound(err) {
			h.notFound(w, r, cur)
		} else {
			h.serverError(w, r, cur, "get grant", err)
		}
		return nil, false
	}
	admin := cur.User.Can(core.RoleAdmin)
	if g.OwnerUserID != cur.User.ID && !admin {
		h.forbidden(w, r, cur)
		return nil, false
	}
	if !singleAddress(g.Prefix) && !admin {
		h.renderGrants(w, r, cur, http.StatusForbidden, grantForm{}, msgEditRangeAdminOnly)
		return nil, false
	}
	return g, true
}

func (h *Handler) renderGrantEdit(w http.ResponseWriter, r *http.Request, cur *auth.Current, status int, d *grantEditData) {
	names, err := h.userNames(r.Context())
	if err != nil {
		h.serverError(w, r, cur, "list users", err)
		return
	}
	d.Owner = names.name(d.Grant.OwnerUserID)
	d.Mine = d.Grant.OwnerUserID == cur.User.ID
	d.CanWildcard = cur.User.Can(core.RoleWildcardAllowed)
	h.render(w, status, "grant_edit", h.newPage(w, r, cur, "Edit address", "grants", d))
}

// grantEditPage shows the edit form for one grant.
func (h *Handler) grantEditPage(w http.ResponseWriter, r *http.Request, cur *auth.Current) {
	g, ok := h.editableGrant(w, r, cur)
	if !ok {
		return
	}
	h.renderGrantEdit(w, r, cur, http.StatusOK, &grantEditData{Grant: *g, Note: g.Note, Wildcard: g.Wildcard, Filter: r.URL.Query().Get("owner")})
}

// grantEdit changes a grant's note and, for users with the wildcard role,
// its wildcard switch. The prefix, owner and enabled state stay as they
// are. A user without the wildcard role never sees the switch; their edit
// keeps it, and asking for wildcard=true answers 403 like adding does.
func (h *Handler) grantEdit(w http.ResponseWriter, r *http.Request, cur *auth.Current) {
	if !limitForm(w, r, maxForm) {
		return
	}
	g, ok := h.editableGrant(w, r, cur)
	if !ok {
		return
	}
	d := &grantEditData{
		Grant:    *g,
		Note:     strings.TrimSpace(r.PostFormValue("note")),
		Wildcard: r.PostFormValue("wildcard") == "true",
		Filter:   r.PostFormValue("owner"),
	}
	back := base + "/grants"
	if d.Filter != "" {
		back += "?owner=" + url.QueryEscape(d.Filter)
	}
	canWildcard := cur.User.Can(core.RoleWildcardAllowed)
	switch {
	case len(d.Note) > maxNote:
		d.Error = fmt.Sprintf("The note is longer than %d characters.", maxNote)
		h.renderGrantEdit(w, r, cur, http.StatusBadRequest, d)
		return
	case d.Wildcard && !canWildcard:
		d.Error = "Your role may not allow wildcard certificates. Ask an administrator for the wildcard role."
		h.renderGrantEdit(w, r, cur, http.StatusForbidden, d)
		return
	case !canWildcard:
		d.Wildcard = g.Wildcard
	}
	var changes []string
	if d.Wildcard != g.Wildcard {
		changes = append(changes, fmt.Sprintf("wildcard %t→%t", g.Wildcard, d.Wildcard))
	}
	if d.Note != g.Note {
		changes = append(changes, "note changed")
	}
	if len(changes) == 0 {
		h.redirect(w, r, back, "ok", fmt.Sprintf("Nothing changed for address %s.", g.Prefix))
		return
	}
	g.Wildcard, g.Note = d.Wildcard, d.Note
	if err := h.Grants.Update(r.Context(), g); err != nil {
		if isNotFound(err) {
			h.redirect(w, r, back, "error", "That address was already removed.")
			return
		}
		h.serverError(w, r, cur, "update grant", err)
		return
	}
	h.record(r, cur, core.AuditGrantChange, fmt.Sprintf("updated grant %s: %s", g.Prefix, strings.Join(changes, ", ")), g.ID)
	h.redirect(w, r, back, "ok", fmt.Sprintf("Saved address %s.", g.Prefix))
}
