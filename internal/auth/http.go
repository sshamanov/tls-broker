package auth

import (
	"context"
	"crypto/subtle"
	"errors"
	"net/http"
	"time"

	"tls-broker/internal/core"
)

// CSRFHeader and CSRFField carry the per-session CSRF token on
// state-changing requests.
const (
	CSRFHeader = "X-CSRF-Token"
	CSRFField  = "csrf_token"

	maxFormBytes = 1 << 20
)

type ctxKey struct{}

// Current is the session and user the middleware loaded.
type Current struct {
	Session *core.Session
	User    *core.User
}

// From returns the loaded session and user, or nil when the request is
// anonymous.
func From(ctx context.Context) *Current {
	c, _ := ctx.Value(ctxKey{}).(*Current)
	return c
}

// SetCookie sets the session cookie. https says the request arrived over TLS
// (directly, or via the trusted proxy with https); Sessions.CookieSecure
// decides whether that, always or never makes the cookie Secure. The cookie
// lasts until expires.
func (s *Service) SetCookie(w http.ResponseWriter, token string, expires time.Time, https bool) {
	c := s.cookie(token, https)
	c.Expires = expires
	c.MaxAge = max(int(expires.Sub(s.Clock.Now())/time.Second), 1)
	http.SetCookie(w, c)
}

// ClearCookie tells the browser to drop the session cookie.
func (s *Service) ClearCookie(w http.ResponseWriter, https bool) {
	c := s.cookie("", https)
	c.MaxAge = -1
	c.Expires = time.Unix(0, 0)
	http.SetCookie(w, c)
}

func (s *Service) cookie(token string, https bool) *http.Cookie {
	cfg := s.Config.Current().Sessions
	name := cfg.CookieName
	if name == "" {
		name = "tls_broker_session"
	}
	return &http.Cookie{
		Name:     name,
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
		Secure:   cfg.CookieSecure.Secure(https),
	}
}

func (s *Service) cookieToken(r *http.Request) string {
	name := s.Config.Current().Sessions.CookieName
	if name == "" {
		name = "tls_broker_session"
	}
	if c, err := r.Cookie(name); err == nil {
		return c.Value
	}
	return ""
}

// Middleware loads the session named by the cookie into the request context
// (see From). A missing, unknown or expired session leaves the request
// anonymous; it does not reject it. Blocked users are loaded too, so callers
// decide with User.Can what they may see.
func (s *Service) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if tok := s.cookieToken(r); tok != "" {
			sess, user, err := s.Session(r.Context(), tok)
			switch {
			case err == nil:
				r = r.WithContext(context.WithValue(r.Context(), ctxKey{}, &Current{sess, user}))
			case errors.Is(err, core.ErrNotFound), errors.Is(err, core.ErrExpired):
			default:
				http.Error(w, "internal error", http.StatusInternalServerError)
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

// RequireRole rejects anonymous requests with 401 and users who are blocked
// or below min with 403. It must run inside Middleware.
func RequireRole(min core.Role) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			cur := From(r.Context())
			if cur == nil {
				http.Error(w, "login required", http.StatusUnauthorized)
				return
			}
			if !cur.User.Can(min) {
				http.Error(w, "forbidden", http.StatusForbidden)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// VerifyCSRF reports whether the request carries the session's CSRF token in
// the X-CSRF-Token header or the csrf_token form field.
func VerifyCSRF(r *http.Request, sess *core.Session) bool {
	if sess == nil || sess.CSRFToken == "" {
		return false
	}
	got := r.Header.Get(CSRFHeader)
	if got == "" {
		r.Body = http.MaxBytesReader(nil, r.Body, maxFormBytes)
		got = r.PostFormValue(CSRFField)
	}
	return subtle.ConstantTimeCompare([]byte(got), []byte(sess.CSRFToken)) == 1
}

// CSRF rejects state-changing requests (anything but GET, HEAD, OPTIONS,
// TRACE) of a logged-in session that lack its CSRF token, with 403. Requests
// without a session pass: there is nothing to forge, and RequireRole refuses
// them where a login is needed. It must run inside Middleware.
func CSRF(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet, http.MethodHead, http.MethodOptions, http.MethodTrace:
		default:
			if cur := From(r.Context()); cur != nil && !VerifyCSRF(r, cur.Session) {
				http.Error(w, "invalid CSRF token", http.StatusForbidden)
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}
