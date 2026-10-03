package ui

import (
	"errors"
	"fmt"
	"net/http"
	"strings"

	"tls-broker/internal/auth"
	"tls-broker/internal/core"
)

type loginData struct {
	Username string
	Next     string
	Error    string
}

func (h *Handler) loginForm(w http.ResponseWriter, r *http.Request, _ *auth.Current) {
	if cur := auth.From(r.Context()); cur != nil {
		http.Redirect(w, r, safeNext(r.URL.Query().Get("next")), http.StatusSeeOther)
		return
	}
	p := h.newPage(w, r, nil, "Log in", "", &loginData{Next: safeNext(r.URL.Query().Get("next"))})
	h.render(w, http.StatusOK, "login", p)
}

func (h *Handler) loginSubmit(w http.ResponseWriter, r *http.Request, _ *auth.Current) {
	// Login CSRF: the session cookie is SameSite=Strict, but refuse an
	// explicit cross-site form post as well.
	if r.Header.Get("Sec-Fetch-Site") == "cross-site" {
		http.Error(w, "cross-site login refused", http.StatusForbidden)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 64<<10)
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	user := strings.TrimSpace(r.PostFormValue("username"))
	next := safeNext(r.PostFormValue("next"))
	fail := func(status int, msg string) {
		p := h.newPage(w, r, nil, "Log in", "", &loginData{Username: user, Next: next, Error: msg})
		h.render(w, status, "login", p)
	}
	login, err := h.Auth.Login(r.Context(), user, r.PostFormValue("password"), sourceIP(r))
	switch {
	case err == nil:
	case auth.AsThrottled(err) != nil:
		t := auth.AsThrottled(err)
		w.Header().Set("Retry-After", fmt.Sprint(int(t.RetryAfter.Seconds())+1))
		fail(http.StatusTooManyRequests, "Too many failed attempts. Wait a minute and try again.")
		return
	case errors.Is(err, core.ErrInvalidCredentials):
		fail(http.StatusUnauthorized, "Invalid username or password.")
		return
	case errors.Is(err, core.ErrDirectoryUnavailable):
		fail(http.StatusServiceUnavailable, "The LDAP directory is unavailable or not configured, so only the local administrator can log in right now.")
		return
	default:
		h.serverError(w, r, nil, "login", err)
		return
	}
	// A browser that still carried a session gets a fresh one; the old row
	// must not stay valid until its expiry.
	if c, err := r.Cookie(h.sessionCookieName()); err == nil && c.Value != "" {
		if err := h.Auth.Logout(r.Context(), c.Value); err != nil {
			h.Logger.Warn("ui: dropping previous session at login", "err", err)
		}
	}
	h.Auth.SetCookie(w, login.Token, login.Session.ExpiresAt, httpsRequest(r))
	if login.User.Blocked {
		h.setFlash(w, "warn", "Your account is blocked. You can view your grants and the activity log only.")
	}
	http.Redirect(w, r, next, http.StatusSeeOther)
}

func (h *Handler) logout(w http.ResponseWriter, r *http.Request, cur *auth.Current) {
	// Logout takes the token from the cookie; the session is already
	// resolved, so drop it by its hash through the Authenticator.
	if c, err := r.Cookie(h.sessionCookieName()); err == nil {
		if err := h.Auth.Logout(r.Context(), c.Value); err != nil {
			h.serverError(w, r, cur, "logout", err)
			return
		}
	}
	h.Auth.ClearCookie(w, httpsRequest(r))
	h.redirect(w, r, base+"/login", "ok", "You have been logged out.")
}

func (h *Handler) sessionCookieName() string {
	if n := h.Config.Current().Sessions.CookieName; n != "" {
		return n
	}
	return "tls_broker_session"
}
