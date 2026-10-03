package auth

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"tls-broker/internal/core"
)

func TestCookieAttributes(t *testing.T) {
	e := newEnv(t)
	e.cfg.Update(func(c *core.Config) { c.Sessions.CookieSecure = core.CookieSecureAuto; c.Sessions.CookieName = "sid" })
	exp := e.clock.Now().Add(time.Hour)

	get := func(secure bool) *http.Cookie {
		w := httptest.NewRecorder()
		e.s.SetCookie(w, "tok", exp, secure)
		cs := w.Result().Cookies()
		if len(cs) != 1 {
			t.Fatalf("cookies %v", cs)
		}
		return cs[0]
	}
	c := get(true)
	if c.Name != "sid" || c.Value != "tok" || !c.HttpOnly || !c.Secure || c.SameSite != http.SameSiteStrictMode || c.Path != "/" || c.MaxAge != 3600 {
		t.Fatalf("%+v", c)
	}
	if get(false).Secure {
		t.Fatal("Secure set for plain http")
	}
	e.cfg.Update(func(c *core.Config) { c.Sessions.CookieSecure = core.CookieSecureAlways })
	if !get(false).Secure {
		t.Fatal("always: Secure missing over plain http")
	}
	e.cfg.Update(func(c *core.Config) { c.Sessions.CookieSecure = core.CookieSecureNever })
	if get(true).Secure {
		t.Fatal("never: Secure set behind TLS")
	}
	e.cfg.Update(func(c *core.Config) { c.Sessions.CookieSecure = "" })
	if c := get(true); !c.Secure || get(false).Secure {
		t.Fatal("zero mode is not auto")
	}

	w := httptest.NewRecorder()
	e.s.ClearCookie(w, true)
	c = w.Result().Cookies()[0]
	if c.Name != "sid" || c.Value != "" || c.MaxAge >= 0 || !c.HttpOnly || c.SameSite != http.SameSiteStrictMode {
		t.Fatalf("clear %+v", c)
	}
}

// stack builds the handler chain the UI uses and returns it with a logged-in
// cookie.
func stack(e *env, min core.Role) (http.Handler, *http.Cookie, *core.Login) {
	l, err := e.s.Login(ctx, "alice", "alicepw", ip1)
	if err != nil {
		panic(err)
	}
	ok := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cur := From(r.Context())
		w.Write([]byte("hi " + cur.User.Username))
	})
	h := e.s.Middleware(CSRF(RequireRole(min)(ok)))
	return h, &http.Cookie{Name: e.cfg.Current().Sessions.CookieName, Value: l.Token}, l
}

func do(h http.Handler, method string, c *http.Cookie, hdr map[string]string, form url.Values) *httptest.ResponseRecorder {
	var body *strings.Reader
	if form != nil {
		body = strings.NewReader(form.Encode())
	} else {
		body = strings.NewReader("")
	}
	r := httptest.NewRequest(method, "/x", body)
	if form != nil {
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	if c != nil {
		r.AddCookie(c)
	}
	for k, v := range hdr {
		r.Header.Set(k, v)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}

func TestMiddlewareAndRequireRole(t *testing.T) {
	e := newEnv(t)
	h, c, l := stack(e, core.RoleNormal)
	if w := do(h, "GET", c, nil, nil); w.Code != 200 || w.Body.String() != "hi alice" {
		t.Fatalf("%d %s", w.Code, w.Body)
	}
	if w := do(h, "GET", nil, nil, nil); w.Code != 401 {
		t.Fatalf("anonymous %d", w.Code)
	}
	if w := do(h, "GET", &http.Cookie{Name: c.Name, Value: "garbage"}, nil, nil); w.Code != 401 {
		t.Fatalf("garbage %d", w.Code)
	}
	// Role too low.
	adminOnly, c2, _ := stack(e, core.RoleAdmin)
	if w := do(adminOnly, "GET", c2, nil, nil); w.Code != 403 {
		t.Fatalf("normal on admin route %d", w.Code)
	}
	// Promotion applies to the existing session at once.
	_ = e.users.SetRole(ctx, l.User.ID, core.RoleAdmin)
	if w := do(adminOnly, "GET", c, nil, nil); w.Code != 200 {
		t.Fatalf("admin %d", w.Code)
	}
	// Blocked takes effect on the next request.
	_ = e.users.SetBlocked(ctx, l.User.ID, true)
	if w := do(adminOnly, "GET", c, nil, nil); w.Code != 403 {
		t.Fatalf("blocked admin %d", w.Code)
	}
	// A blocked user is still loaded into the context (public views).
	var seen *Current
	e.s.Middleware(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) { seen = From(r.Context()) })).
		ServeHTTP(httptest.NewRecorder(), func() *http.Request {
			r := httptest.NewRequest("GET", "/", nil)
			r.AddCookie(c)
			return r
		}())
	if seen == nil || !seen.User.Blocked {
		t.Fatalf("blocked user not loaded: %+v", seen)
	}
	// Expired session is anonymous.
	e.clock.Advance(365 * 24 * time.Hour)
	if w := do(h, "GET", c, nil, nil); w.Code != 401 {
		t.Fatalf("expired %d", w.Code)
	}
}

func TestCSRF(t *testing.T) {
	e := newEnv(t)
	h, c, l := stack(e, core.RoleNormal)
	tok := l.Session.CSRFToken

	if w := do(h, "POST", c, nil, nil); w.Code != 403 {
		t.Fatalf("missing token %d", w.Code)
	}
	if w := do(h, "POST", c, map[string]string{CSRFHeader: tok + "x"}, nil); w.Code != 403 {
		t.Fatalf("wrong header %d", w.Code)
	}
	if w := do(h, "POST", c, nil, url.Values{CSRFField: {"wrong"}}); w.Code != 403 {
		t.Fatalf("wrong field %d", w.Code)
	}
	if w := do(h, "POST", c, nil, url.Values{"other": {tok}}); w.Code != 403 {
		t.Fatalf("token under wrong field %d", w.Code)
	}
	if w := do(h, "POST", c, map[string]string{CSRFHeader: tok}, nil); w.Code != 200 {
		t.Fatalf("header %d", w.Code)
	}
	if w := do(h, "POST", c, nil, url.Values{CSRFField: {tok}}); w.Code != 200 {
		t.Fatalf("field %d", w.Code)
	}
	for _, m := range []string{"PUT", "PATCH", "DELETE"} {
		if w := do(h, m, c, nil, nil); w.Code != 403 {
			t.Fatalf("%s %d", m, w.Code)
		}
	}
	for _, m := range []string{"GET", "HEAD", "OPTIONS"} {
		if w := do(h, m, c, nil, nil); w.Code != 200 {
			t.Fatalf("%s %d", m, w.Code)
		}
	}
	// A token from another session does not work.
	_, _, other := stack(e, core.RoleNormal)
	if w := do(h, "POST", c, map[string]string{CSRFHeader: other.Session.CSRFToken}, nil); w.Code != 403 {
		t.Fatalf("other session token %d", w.Code)
	}
	// No session: CSRF lets it through, RequireRole refuses.
	if w := do(h, "POST", nil, nil, nil); w.Code != 401 {
		t.Fatalf("anonymous POST %d", w.Code)
	}
}
