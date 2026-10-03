// Package ui is the web UI: server-rendered html/template pages under /ui/,
// embedded assets and one small stylesheet. There is no JavaScript build step;
// the only script is a few lines that ask for confirmation before destructive
// forms (static/ui.js), served from the same origin so the CSP needs no
// inline script.
//
// The handler depends only on the ports of package core (plus the concrete
// auth.Service for the cookie helpers and middleware). Every page sits behind
// auth.Middleware, auth.CSRF and a role check; see docs/ui.md for the page map.
package ui

import (
	"bytes"
	"context"
	"embed"
	"errors"
	"fmt"
	"html/template"
	"io/fs"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"sync"
	"time"

	"crypto/sha256"
	"encoding/hex"

	"tls-broker/internal/auth"
	"tls-broker/internal/core"
	"tls-broker/internal/httpx"
)

//go:embed templates/*.html
var templateFS embed.FS

//go:embed static
var staticFS embed.FS

// Paths of the UI.
const (
	base       = "/ui"
	staticPath = "/ui/static/"
)

// KeyRotator is the hook for direct-mode key rotation. internal/direct is
// expected to provide it in a later wave; while Deps.Rotator is nil the
// certificates page shows no rotate button and the route answers 404.
type KeyRotator interface {
	// Rotate generates a new key for the direct-cache identifier and
	// issues a fresh certificate for it.
	Rotate(ctx context.Context, identifier string) error
}

// ZoneStatus is the hosted zone in effect for one managed zone, as the
// DNS-01 engine reports it (dns01.ZoneStatus has the same shape).
type ZoneStatus struct {
	Name         string
	HostedZoneID string // effective ID; "" while discovery has not succeeded
	Resolved     bool   // true: discovered by name; false: configured
	Err          string // why discovery failed (only when HostedZoneID is "")
}

// ZoneStatusSource reports the hosted zone in effect for every managed zone.
type ZoneStatusSource interface {
	ZoneStatuses() []ZoneStatus
}

// Deps are the collaborators of the UI. Everything except Zones, Rotator and
// Logger is required.
type Deps struct {
	Auth      *auth.Service
	Config    core.ConfigSource
	Admin     core.ConfigAdmin
	Secrets   core.SecretStore
	LDAP      core.LDAPTester
	CAA       core.CAAChecker
	Providers core.Providers
	Scheduler core.Scheduler
	Audit     core.AuditReader
	Auditor   core.Auditor
	Users     core.UserStore
	Grants    core.GrantStore
	Certs     core.CertificateStore
	Orders    core.OrderStore
	Direct    core.DirectStore
	Lineages  core.LineageStore
	Clock     core.Clock

	// Zones is optional; when nil the dashboard shows the configured hosted
	// zone IDs only.
	Zones ZoneStatusSource
	// Rotator is optional; see KeyRotator.
	Rotator KeyRotator
	// Banners are process-level warnings shown at the top of every page,
	// logged in or not (for example "the DNS gate is mocked"). Optional.
	Banners []string
	Logger  *slog.Logger
}

// Handler serves everything under /ui/. Mount it at "/ui/" (and "/ui").
type Handler struct {
	Deps
	tmpl   map[string]*template.Template
	mux    *http.ServeMux
	root   http.Handler
	static http.Handler
	assets string // content hash used as cache-busting query
	// patterns are the "METHOD /path" patterns passed to route, used to
	// keep 405 answers for POST-only paths next to the GET catch-all.
	patterns []string

	mu       sync.Mutex
	ldapAt   time.Time // last "Test LDAP" run since start; zero when none
	ldapErr  string
	ldapDone bool
}

// New builds the handler.
func New(d Deps) (*Handler, error) {
	if d.Logger == nil {
		d.Logger = slog.Default()
	}
	if d.Clock == nil {
		d.Clock = core.SystemClock{}
	}
	h := &Handler{Deps: d, mux: http.NewServeMux()}
	if err := h.loadTemplates(); err != nil {
		return nil, err
	}
	sub, err := fs.Sub(staticFS, "static")
	if err != nil {
		return nil, err
	}
	h.static = http.StripPrefix(staticPath, http.FileServerFS(sub))
	sum := sha256.New()
	_ = fs.WalkDir(sub, ".", func(p string, e fs.DirEntry, err error) error {
		if err == nil && !e.IsDir() {
			b, _ := fs.ReadFile(sub, p)
			sum.Write(b)
		}
		return nil
	})
	h.assets = hex.EncodeToString(sum.Sum(nil))[:12]
	h.routes()
	h.root = securityHeaders(d.Auth.Middleware(auth.CSRF(h.mux)))
	return h, nil
}

// ServeHTTP implements http.Handler.
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) { h.root.ServeHTTP(w, r) }

func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hd := w.Header()
		hd.Set("Content-Security-Policy", "default-src 'none'; style-src 'self'; script-src 'self'; img-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'")
		hd.Set("X-Frame-Options", "DENY")
		hd.Set("X-Content-Type-Options", "nosniff")
		hd.Set("Referrer-Policy", "same-origin")
		hd.Set("Cross-Origin-Opener-Policy", "same-origin")
		hd.Set("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
		if !strings.HasPrefix(r.URL.Path, staticPath) {
			hd.Set("Cache-Control", "no-store")
		}
		next.ServeHTTP(w, r)
	})
}

// access is the role needed by a route.
type access int

const (
	// accessAnon: no login needed.
	accessAnon access = iota
	// accessAny: any logged-in user, blocked ones included (views the
	// architecture allows blocked users: own grants read-only, public
	// audit, dashboard banner).
	accessAny
	// accessUser: logged in and not blocked.
	accessUser
	// accessAdmin: logged in, not blocked, admin.
	accessAdmin
)

type handlerFunc func(w http.ResponseWriter, r *http.Request, cur *auth.Current)

// route registers pattern ("GET /ui/x"; the method is part of it, so other
// methods get 405) behind the access check.
func (h *Handler) route(pattern string, level access, fn handlerFunc) {
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fn(w, r, auth.From(r.Context()))
	})
	var guarded http.Handler = inner
	switch level {
	case accessUser:
		guarded = auth.RequireRole(core.RoleNormal)(inner)
	case accessAdmin:
		guarded = auth.RequireRole(core.RoleAdmin)(inner)
	}
	h.patterns = append(h.patterns, pattern)
	h.mux.HandleFunc(pattern, func(w http.ResponseWriter, r *http.Request) {
		cur := auth.From(r.Context())
		if level == accessAnon {
			inner.ServeHTTP(w, r)
			return
		}
		if cur == nil {
			if r.Method == http.MethodGet || r.Method == http.MethodHead {
				http.Redirect(w, r, base+"/login?next="+url.QueryEscape(r.URL.RequestURI()), http.StatusSeeOther)
			} else {
				http.Error(w, "login required", http.StatusUnauthorized)
			}
			return
		}
		min := core.RoleNormal
		if level == accessAdmin {
			min = core.RoleAdmin
		}
		if level != accessAny && !cur.User.Can(min) {
			h.forbidden(w, r, cur)
			return
		}
		guarded.ServeHTTP(w, r)
	})
}

func (h *Handler) routes() {
	h.mux.Handle("GET "+staticPath, http.HandlerFunc(h.serveStatic))
	h.mux.HandleFunc("GET /ui", func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, base+"/", http.StatusSeeOther) })

	h.route("GET /ui/login", accessAnon, h.loginForm)
	h.route("POST /ui/login", accessAnon, h.loginSubmit)
	h.route("POST /ui/logout", accessAny, h.logout)

	h.route("GET /ui/{$}", accessAny, h.dashboard)

	h.route("GET /ui/grants", accessAny, h.grantsPage)
	h.route("POST /ui/grants", accessUser, h.grantCreate)
	h.route("POST /ui/grants/{id}/{action}", accessUser, h.grantAction)

	h.route("GET /ui/certificates", accessUser, h.certificates)
	h.route("POST /ui/certificates/rotate", accessAdmin, h.rotateKey)

	h.route("GET /ui/audit", accessAny, h.auditPage)

	h.route("GET /ui/admin/users", accessAdmin, h.usersPage)
	h.route("POST /ui/admin/users/{id}/{action}", accessAdmin, h.userAction)
	h.route("GET /ui/admin/grants", accessAdmin, h.adminGrants)
	h.route("POST /ui/admin/grants/{id}/{action}", accessAdmin, h.adminGrantAction)

	h.route("GET /ui/admin/config", accessAdmin, h.configPage)
	h.route("POST /ui/admin/config/validate", accessAdmin, h.configValidate)
	h.route("POST /ui/admin/config/activate", accessAdmin, h.configActivate)
	h.route("POST /ui/admin/config/test-ldap", accessAdmin, h.configTestLDAP)
	h.route("POST /ui/admin/config/rollback", accessAdmin, h.configRollback)
	h.route("GET /ui/admin/secrets", accessAdmin, h.secretsPage)
	h.route("POST /ui/admin/secrets", accessAdmin, h.secretSet)
	h.route("POST /ui/admin/secrets/delete", accessAdmin, h.secretDelete)

	h.route("GET /ui/admin/providers", accessAdmin, h.providersPage)

	// Everything else under /ui/ is the styled 404. "GET /ui/{$}" (the
	// dashboard) and the other exact patterns are more specific and win. A
	// GET on a POST-only path would match the catch-all too, so those paths
	// get an explicit 405 first.
	get := map[string]bool{}
	for _, p := range h.patterns {
		if m, path, ok := strings.Cut(p, " "); ok && m == http.MethodGet {
			get[path] = true
		}
	}
	for _, p := range h.patterns {
		if m, path, ok := strings.Cut(p, " "); ok && m == http.MethodPost && !get[path] {
			h.mux.HandleFunc(http.MethodGet+" "+path, methodNotAllowed)
		}
	}
	h.route("GET /ui/", accessAnon, h.notFound)
}

func methodNotAllowed(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Allow", http.MethodPost)
	http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
}

func (h *Handler) serveStatic(w http.ResponseWriter, r *http.Request) {
	// The asset URLs carry a content hash (?v=...), so they can be cached
	// for a long time; a changed file gets a new URL.
	w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
	h.static.ServeHTTP(w, r)
}

// ---------------------------------------------------------------------------
// Rendering
// ---------------------------------------------------------------------------

// page is the data every template receives; page-specific data is in Data.
type page struct {
	Title   string
	Nav     string
	User    *core.User
	CSRF    string
	Flash   *flash
	Blocked bool
	Admin   bool
	Assets  string
	Banners []string
	Data    any
}

type flash struct {
	Kind string // ok | error | warn
	Text string
}

const flashCookie = "ui_flash"

func (h *Handler) setFlash(w http.ResponseWriter, kind, text string) {
	if len(text) > 600 {
		text = text[:600] + "..."
	}
	http.SetCookie(w, &http.Cookie{
		Name: flashCookie, Value: url.QueryEscape(kind + "|" + text), Path: base + "/",
		HttpOnly: true, SameSite: http.SameSiteStrictMode, MaxAge: 60,
	})
}

// takeFlash reads and clears the flash cookie.
func (h *Handler) takeFlash(w http.ResponseWriter, r *http.Request) *flash {
	c, err := r.Cookie(flashCookie)
	if err != nil {
		return nil
	}
	http.SetCookie(w, &http.Cookie{Name: flashCookie, Path: base + "/", MaxAge: -1, HttpOnly: true, SameSite: http.SameSiteStrictMode})
	v, err := url.QueryUnescape(c.Value)
	if err != nil {
		return nil
	}
	kind, text, ok := strings.Cut(v, "|")
	if !ok || (kind != "ok" && kind != "error" && kind != "warn") {
		return nil
	}
	return &flash{Kind: kind, Text: text}
}

func (h *Handler) newPage(w http.ResponseWriter, r *http.Request, cur *auth.Current, title, nav string, data any) *page {
	p := &page{Title: title, Nav: nav, Assets: h.assets, Banners: h.Banners, Data: data}
	if cur != nil {
		p.User = cur.User
		p.CSRF = cur.Session.CSRFToken
		p.Blocked = cur.User.Blocked
		p.Admin = cur.User.Can(core.RoleAdmin)
	}
	p.Flash = h.takeFlash(w, r)
	return p
}

func (h *Handler) render(w http.ResponseWriter, status int, name string, p *page) {
	t, ok := h.tmpl[name]
	if !ok {
		h.Logger.Error("ui: unknown template", "name", name)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	var buf bytes.Buffer
	if err := t.ExecuteTemplate(&buf, "layout", p); err != nil {
		h.Logger.Error("ui: render failed", "template", name, "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	_, _ = w.Write(buf.Bytes())
}

func (h *Handler) forbidden(w http.ResponseWriter, r *http.Request, cur *auth.Current) {
	p := h.newPage(w, r, cur, "Forbidden", "", nil)
	h.render(w, http.StatusForbidden, "forbidden", p)
}

func (h *Handler) notFound(w http.ResponseWriter, r *http.Request, cur *auth.Current) {
	p := h.newPage(w, r, cur, "Not found", "", nil)
	h.render(w, http.StatusNotFound, "notfound", p)
}

// serverError logs err and shows a generic page; internal text never reaches
// the browser.
func (h *Handler) serverError(w http.ResponseWriter, r *http.Request, cur *auth.Current, what string, err error) {
	id := httpx.RequestIDFrom(r.Context())
	h.Logger.Error("ui: request failed", "what", what, "path", r.URL.Path, "error", err, "request_id", id)
	p := h.newPage(w, r, cur, "Error", "", map[string]string{"What": what, "RequestID": id})
	h.render(w, http.StatusInternalServerError, "error", p)
}

func (h *Handler) redirect(w http.ResponseWriter, r *http.Request, to, kind, msg string) {
	if msg != "" {
		h.setFlash(w, kind, msg)
	}
	http.Redirect(w, r, to, http.StatusSeeOther)
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// sourceIP is the client address for audit and login: the real IP when the
// RealIP middleware ran, else the TCP peer.
func sourceIP(r *http.Request) netip.Addr {
	if ip, ok := httpx.SourceIP(r.Context()); ok {
		return ip
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	a, err := netip.ParseAddr(host)
	if err != nil {
		return netip.Addr{}
	}
	return a.Unmap()
}

// record writes a control-plane audit event. Grant, user and config changes
// are admin-visible only (architecture §14).
func (h *Handler) record(r *http.Request, cur *auth.Current, typ, detail string, grantID int64) {
	h.Auditor.Record(r.Context(), core.AuditEvent{
		Time:       h.Clock.Now(),
		Type:       typ,
		Visibility: core.AuditVisibilityAdmin,
		Mode:       core.ModeUI,
		SourceIP:   sourceIP(r).String(),
		Username:   cur.User.Username,
		GrantID:    grantID,
		Result:     core.AuditResultOK,
		Detail:     detail,
	})
}

func safeNext(next string) string {
	if strings.HasPrefix(next, base+"/") && !strings.ContainsAny(next, "\\\r\n") && !strings.HasPrefix(next, "//") {
		return next
	}
	return base + "/"
}

func formInt(r *http.Request, name string) (int64, bool) {
	var n int64
	if _, err := fmt.Sscanf(r.PathValue(name), "%d", &n); err != nil || n <= 0 {
		return 0, false
	}
	return n, true
}

func isNotFound(err error) bool { return errors.Is(err, core.ErrNotFound) }

func (h *Handler) loadTemplates() error {
	funcs := template.FuncMap{
		"ts":        tsHTML,
		"rel":       func(t time.Time) string { return relTime(h.Clock.Now(), t) },
		"dur":       fmtDur,
		"join":      strings.Join,
		"role":      func(r core.Role) string { return strings.ReplaceAll(string(r), "_", " ") },
		"pct":       pct,
		"pctOf":     func(n, p int) int { return n * p / 100 },
		"exhausted": budgetExhausted,
		"inc":       func(i int) int { return i + 1 },
		"isZero":    func(t time.Time) bool { return t.IsZero() },
		"lower":     strings.ToLower,
		"roleStr":   func(r core.Role) string { return string(r) },
	}
	entries, err := fs.Glob(templateFS, "templates/*.html")
	if err != nil {
		return err
	}
	layout, err := template.New("layout").Funcs(funcs).ParseFS(templateFS, "templates/_layout.html")
	if err != nil {
		return err
	}
	h.tmpl = map[string]*template.Template{}
	for _, e := range entries {
		name := strings.TrimSuffix(strings.TrimPrefix(e, "templates/"), ".html")
		if strings.HasPrefix(name, "_") {
			continue
		}
		t, err := layout.Clone()
		if err != nil {
			return err
		}
		if _, err := t.ParseFS(templateFS, e); err != nil {
			return fmt.Errorf("ui: template %s: %w", name, err)
		}
		h.tmpl[name] = t
	}
	return nil
}

func fmtTime(t time.Time) string {
	if t.IsZero() {
		return "-"
	}
	return t.UTC().Format("2006-01-02 15:04:05 UTC")
}

// tsHTML renders a timestamp as a <time> element: machine-readable datetime,
// and styled nowrap so a time never wraps into four lines in a narrow column.
// Every byte comes from the time format, so it is safe to mark as HTML.
func tsHTML(t time.Time) template.HTML {
	if t.IsZero() {
		return "-"
	}
	return template.HTML(`<time datetime="` + t.UTC().Format(time.RFC3339) + `">` + fmtTime(t) + `</time>`)
}

func relTime(now, t time.Time) string {
	if t.IsZero() {
		return ""
	}
	d := t.Sub(now)
	if d >= 0 {
		return "in " + fmtDur(d)
	}
	return fmtDur(-d) + " ago"
}

func fmtDur(d time.Duration) string {
	switch {
	case d < time.Minute:
		return fmt.Sprintf("%ds", int(d.Seconds()))
	case d < time.Hour:
		return fmt.Sprintf("%dm", int(d.Minutes()))
	case d < 48*time.Hour:
		return fmt.Sprintf("%dh%02dm", int(d.Hours()), int(d.Minutes())%60)
	default:
		return fmt.Sprintf("%dd", int(d.Hours()/24))
	}
}

// budgetExhausted reports a budget with nothing left in its window.
func budgetExhausted(b core.BudgetUsage) bool { return b.Limit > 0 && b.Used >= b.Limit }

func pct(used, limit int) int {
	if limit <= 0 {
		return 0
	}
	p := used * 100 / limit
	return min(p, 100)
}

func httpsRequest(r *http.Request) bool { return r.TLS != nil || httpx.IsHTTPS(r.Context()) }

func contextTimeout(r *http.Request) (context.Context, context.CancelFunc) {
	return context.WithTimeout(r.Context(), probeTimeout)
}
