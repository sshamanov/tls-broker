package ui

import (
	"fmt"
	"net/http"

	"tls-broker/internal/auth"
	"tls-broker/internal/core"
)

type usersData struct {
	Users []core.User
	Roles []core.Role
}

func (h *Handler) usersPage(w http.ResponseWriter, r *http.Request, cur *auth.Current) {
	users, err := h.Users.List(r.Context())
	if err != nil {
		h.serverError(w, r, cur, "list users", err)
		return
	}
	d := &usersData{Users: users, Roles: []core.Role{core.RoleNormal, core.RoleWildcardAllowed, core.RoleAdmin}}
	h.render(w, http.StatusOK, "admin_users", h.newPage(w, r, cur, "Users", "admin-users", d))
}

// userAction handles role, block and unblock. The change is stored at once
// and applies to the user's existing sessions, because auth reads the user
// afresh on every request.
func (h *Handler) userAction(w http.ResponseWriter, r *http.Request, cur *auth.Current) {
	back := base + "/admin/users"
	id, ok := formInt(r, "id")
	if !ok {
		h.notFound(w, r, cur)
		return
	}
	if !limitForm(w, r, maxForm) {
		return
	}
	u, err := h.Users.Get(r.Context(), id)
	if err != nil {
		if isNotFound(err) {
			h.notFound(w, r, cur)
		} else {
			h.serverError(w, r, cur, "get user", err)
		}
		return
	}
	refuse := func(msg string) { h.redirect(w, r, back, "error", msg) }
	if u.Local {
		refuse("The local break-glass administrator cannot be changed here; it is always an unblocked admin.")
		return
	}
	if u.ID == cur.User.ID {
		refuse("You cannot change your own role or blocked state.")
		return
	}
	var detail string
	switch r.PathValue("action") {
	case "role":
		role := core.Role(r.PostFormValue("role"))
		if !role.Valid() {
			refuse("Unknown role.")
			return
		}
		if err := h.Users.SetRole(r.Context(), u.ID, role); err != nil {
			h.userErr(w, r, cur, err)
			return
		}
		detail = fmt.Sprintf("%s: role=%s", u.Username, role)
	case "block", "unblock":
		blocked := r.PathValue("action") == "block"
		if err := h.Users.SetBlocked(r.Context(), u.ID, blocked); err != nil {
			h.userErr(w, r, cur, err)
			return
		}
		detail = fmt.Sprintf("%s: blocked=%t", u.Username, blocked)
	default:
		h.notFound(w, r, cur)
		return
	}
	h.record(r, cur, core.AuditUserChange, detail, 0)
	h.redirect(w, r, back, "ok", "Saved: "+detail+".")
}

func (h *Handler) userErr(w http.ResponseWriter, r *http.Request, cur *auth.Current, err error) {
	if isNotFound(err) {
		h.redirect(w, r, base+"/admin/users", "error", "That user no longer exists.")
		return
	}
	h.serverError(w, r, cur, "change user", err)
}

type providersData struct {
	Snapshot core.SchedulerSnapshot
	Configs  map[string]core.ProviderConfig
	Accounts map[string]accountView
	Order    []string // enabled providers in preference order
}

// providersPage shows the scheduler's view of every provider. The scheduler
// exposes no circuit reset in core, so there is no reset action.
func (h *Handler) providersPage(w http.ResponseWriter, r *http.Request, cur *auth.Current) {
	cfg := h.Config.Current()
	d := &providersData{Snapshot: h.Scheduler.Snapshot(), Configs: map[string]core.ProviderConfig{}, Accounts: map[string]accountView{}}
	for _, p := range cfg.Providers {
		d.Configs[p.Name] = p
	}
	for _, p := range cfg.EnabledProviders() {
		d.Order = append(d.Order, p.Name)
	}
	ctx, cancel := contextTimeout(r)
	defer cancel()
	for _, pr := range h.Providers.Enabled() {
		av := accountView{Provider: pr.Name()}
		if u, err := pr.AccountURL(ctx); err != nil {
			av.Err = err.Error()
		} else {
			av.URL = u
		}
		d.Accounts[pr.Name()] = av
	}
	h.render(w, http.StatusOK, "admin_providers", h.newPage(w, r, cur, "Providers", "admin-providers", d))
}
