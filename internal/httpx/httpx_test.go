package httpx

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
	"time"

	"tls-broker/internal/core"
)

func resolver() *Resolver {
	return NewResolver(Options{
		TrustedProxies: []netip.Prefix{netip.MustParsePrefix("127.0.0.1/32"), netip.MustParsePrefix("10.9.0.0/24")},
		RealIPHeader:   "X-Real-IP",
	})
}

func req(remote string, hdr ...string) *http.Request {
	r := httptest.NewRequest("GET", "/x", nil)
	r.RemoteAddr = remote
	for i := 0; i+1 < len(hdr); i += 2 {
		r.Header.Add(hdr[i], hdr[i+1])
	}
	return r
}

func TestResolve(t *testing.T) {
	tests := []struct {
		name   string
		r      *http.Request
		ip     string // "" = invalid
		flag   string
		https  bool
		truste bool
	}{
		{"untrusted peer, no header", req("192.168.1.5:4000"), "192.168.1.5", "", false, false},
		{"spoofed real-ip from untrusted peer", req("192.168.1.5:4000", "X-Real-IP", "10.0.0.1"), "192.168.1.5", "", false, false},
		{"spoofed XFF and proto from untrusted peer", req("192.168.1.5:4000", "X-Forwarded-For", "10.0.0.1", "X-Forwarded-Proto", "https"), "192.168.1.5", "", false, false},
		{"trusted peer uses header", req("127.0.0.1:1", "X-Real-IP", "10.1.2.3"), "10.1.2.3", "", false, true},
		{"trusted CIDR peer", req("10.9.0.7:1", "X-Real-IP", " 10.1.2.3 "), "10.1.2.3", "", false, true},
		{"trusted proto https", req("127.0.0.1:1", "X-Real-IP", "10.1.2.3", "X-Forwarded-Proto", "https"), "10.1.2.3", "", true, true},
		{"trusted proto http", req("127.0.0.1:1", "X-Real-IP", "10.1.2.3", "X-Forwarded-Proto", "http"), "10.1.2.3", "", false, true},
		{"XFF ignored from trusted peer", req("127.0.0.1:1", "X-Forwarded-For", "10.5.5.5, 10.6.6.6"), "127.0.0.1", FlagHeaderMissing, false, true},
		{"chain in real-ip header rejected", req("127.0.0.1:1", "X-Real-IP", "10.1.2.3, 10.4.4.4"), "", FlagHeaderInvalid, false, true},
		{"duplicate header rejected", req("127.0.0.1:1", "X-Real-IP", "10.1.2.3", "X-Real-IP", "10.4.4.4"), "", FlagHeaderInvalid, false, true},
		{"garbage header", req("127.0.0.1:1", "X-Real-IP", "nope"), "", FlagHeaderInvalid, false, true},
		{"ipv6 header", req("127.0.0.1:1", "X-Real-IP", "2001:db8::1"), "", FlagHeaderNotIPv4, false, true},
		{"mapped ipv6 header", req("127.0.0.1:1", "X-Real-IP", "::ffff:10.1.2.3"), "10.1.2.3", "", false, true},
		{"ipv6 peer untrusted", req("[2001:db8::1]:1"), "", FlagPeerNotIPv4, false, false},
		{"mapped ipv6 peer", req("[::ffff:192.168.1.5]:1"), "192.168.1.5", "", false, false},
		{"unparsable peer", req("garbage"), "", FlagPeerNotIPv4, false, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			c := resolver().Resolve(tc.r)
			got := ""
			if c.IP.IsValid() {
				got = c.IP.String()
			}
			if got != tc.ip || c.Flag != tc.flag || c.HTTPS != tc.https || c.Trusted != tc.truste {
				t.Fatalf("got %+v", c)
			}
			if c.Valid() != (tc.ip != "") {
				t.Fatal("Valid mismatch")
			}
		})
	}
}

func TestResolveNoTrustedProxies(t *testing.T) {
	r := NewResolver(Options{RealIPHeader: "X-Real-IP"})
	c := r.Resolve(req("127.0.0.1:1", "X-Real-IP", "10.1.2.3", "X-Forwarded-Proto", "https"))
	if c.IP.String() != "127.0.0.1" || c.HTTPS || c.Trusted {
		t.Fatalf("%+v", c)
	}
}

func TestResolveTLSAndCustomProto(t *testing.T) {
	r := NewResolver(Options{TrustedProxies: []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8")}, RealIPHeader: "X-Real-IP", ProtoHeader: "X-Scheme"})
	if c := r.Resolve(req("127.0.0.1:1", "X-Real-IP", "10.0.0.1", "X-Scheme", "HTTPS")); !c.HTTPS {
		t.Fatal("custom proto header ignored")
	}
	rq := req("192.168.0.1:1")
	rq.TLS = &tlsState
	if c := r.Resolve(rq); !c.HTTPS {
		t.Fatal("direct TLS not detected")
	}
}

func TestRealIPMiddlewareAndRequireIPv4(t *testing.T) {
	var gotIP netip.Addr
	var ok, https bool
	h := RealIP(resolver())(RequireIPv4(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotIP, ok = SourceIP(r.Context())
		https = IsHTTPS(r.Context())
	})))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req("127.0.0.1:1", "X-Real-IP", "10.1.2.3", "X-Forwarded-Proto", "https"))
	if !ok || gotIP.String() != "10.1.2.3" || !https {
		t.Fatalf("%v %v %v", gotIP, ok, https)
	}
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req("127.0.0.1:1", "X-Real-IP", "fe80::1"))
	if rec.Code != 403 || rec.Header().Get("Content-Type") != core.ProblemContentType {
		t.Fatalf("%d %v", rec.Code, rec.Header())
	}
	if _, ok := SourceIP(context.Background()); ok {
		t.Fatal("bare context has no source")
	}
}

func TestRequestID(t *testing.T) {
	var id string
	h := RealIP(resolver())(RequestID(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { id = RequestIDFrom(r.Context()) })))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req("127.0.0.1:1", "X-Real-IP", "10.0.0.1", "X-Request-ID", "abc-123"))
	if id != "abc-123" || rec.Header().Get(RequestIDHeader) != "abc-123" {
		t.Fatalf("trusted id lost: %q", id)
	}
	h.ServeHTTP(httptest.NewRecorder(), req("192.168.0.9:1", "X-Request-ID", "abc-123"))
	if id == "abc-123" || len(id) != 16 {
		t.Fatalf("untrusted id kept: %q", id)
	}
	h.ServeHTTP(httptest.NewRecorder(), req("127.0.0.1:1", "X-Real-IP", "10.0.0.1", "X-Request-ID", "bad id\n"))
	if len(id) != 16 {
		t.Fatalf("malformed id kept: %q", id)
	}
}

func TestRecover(t *testing.T) {
	var buf bytes.Buffer
	log := slog.New(slog.NewTextHandler(&buf, nil))
	h := Recover(log)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { panic("boom") }))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req("1.2.3.4:5"))
	if rec.Code != 500 || rec.Header().Get("Content-Type") != core.ProblemContentType || strings.Contains(rec.Body.String(), "boom") {
		t.Fatalf("%d %s", rec.Code, rec.Body)
	}
	if !strings.Contains(buf.String(), "boom") {
		t.Fatalf("panic not logged: %s", buf.String())
	}
	// started response: nothing appended
	h = Recover(log)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(202); panic("late") }))
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req("1.2.3.4:5"))
	if rec.Code != 202 || rec.Body.Len() != 0 {
		t.Fatalf("%d %s", rec.Code, rec.Body)
	}
	// abort passes through
	defer func() {
		if recover() != http.ErrAbortHandler {
			t.Fatal("ErrAbortHandler swallowed")
		}
	}()
	Recover(log)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { panic(http.ErrAbortHandler) })).ServeHTTP(httptest.NewRecorder(), req("1.2.3.4:5"))
}

func TestAccessLog(t *testing.T) {
	var buf bytes.Buffer
	log := slog.New(slog.NewJSONHandler(&buf, nil))
	h := RealIP(resolver())(RequestID(AccessLog(log)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(404)
		_, _ = w.Write([]byte("nope"))
	}))))
	r := req("127.0.0.1:1", "X-Real-IP", "10.1.2.3")
	r.URL.RawQuery = "token=secret"
	h.ServeHTTP(httptest.NewRecorder(), r)
	var m map[string]any
	if err := json.Unmarshal(buf.Bytes(), &m); err != nil {
		t.Fatal(err)
	}
	if m["status"] != float64(404) || m["bytes"] != float64(4) || m["source_ip"] != "10.1.2.3" ||
		m["path"] != "/x" || m["level"] != "WARN" || m["request_id"] == "" {
		t.Fatalf("%v", m)
	}
	if strings.Contains(buf.String(), "secret") {
		t.Fatal("query logged")
	}
	// Successful liveness probes log at debug; failed ones keep their level.
	for _, c := range []struct {
		status int
		level  string
	}{{200, "DEBUG"}, {503, "ERROR"}} {
		buf.Reset()
		log := slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug}))
		h := AccessLog(log)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(c.status) }))
		r := req("1.2.3.4:5")
		r.URL.Path = HealthPath
		h.ServeHTTP(httptest.NewRecorder(), r)
		if err := json.Unmarshal(buf.Bytes(), &m); err != nil {
			t.Fatal(err)
		}
		if m["level"] != c.level {
			t.Fatalf("healthz %d logged at %v, want %s", c.status, m["level"], c.level)
		}
	}
}

func TestMaxBody(t *testing.T) {
	var readErr error
	h := MaxBody(10)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, readErr = io.ReadAll(r.Body)
		if IsBodyTooLarge(readErr) {
			WriteProblemStatus(w, 413, core.ProblemMalformed, "too large")
		}
	}))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("POST", "/", strings.NewReader("0123456789")))
	if readErr != nil || rec.Code != 200 {
		t.Fatalf("%v %d", readErr, rec.Code)
	}
	r := httptest.NewRequest("POST", "/", io.NopCloser(strings.NewReader("0123456789abc")))
	r.ContentLength = -1 // unknown length: limited while reading
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, r)
	if rec.Code != 413 {
		t.Fatalf("%d", rec.Code)
	}
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("POST", "/", strings.NewReader("0123456789abc")))
	if rec.Code != 413 {
		t.Fatalf("declared length: %d", rec.Code)
	}
}

func TestPathTimeouts(t *testing.T) {
	var got time.Duration
	var has bool
	h := PathTimeouts(10*time.Second,
		TimeoutRule{Prefix: "/acme/", Timeout: 5 * time.Minute},
		TimeoutRule{Prefix: "/acme/directory", Timeout: 5 * time.Second},
		TimeoutRule{Prefix: "/cert/", Timeout: 0},
	)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var dl time.Time
		dl, has = r.Context().Deadline()
		got = time.Until(dl)
	}))
	do := func(path string) {
		has = false
		h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("GET", path, nil))
	}
	near := func(d, want time.Duration) bool { return d > want-2*time.Second && d <= want }
	do("/ui/x")
	if !has || !near(got, 10*time.Second) {
		t.Fatalf("default: %v %v", has, got)
	}
	do("/acme/finalize/1")
	if !has || !near(got, 5*time.Minute) {
		t.Fatalf("long: %v %v", has, got)
	}
	do("/acme/directory")
	if !has || !near(got, 5*time.Second) {
		t.Fatalf("longest prefix: %v %v", has, got)
	}
	do("/cert/a.example.com")
	if has {
		t.Fatal("zero timeout must not set a deadline")
	}
}

func TestWriteProblem(t *testing.T) {
	rec := httptest.NewRecorder()
	WriteProblem(rec, core.NewProblem(core.ProblemRateLimited, "slow down").WithRetryAfter(1500*time.Millisecond))
	if rec.Code != 429 || rec.Header().Get("Content-Type") != "application/problem+json" || rec.Header().Get("Retry-After") != "2" {
		t.Fatalf("%d %v", rec.Code, rec.Header())
	}
	var p core.Problem
	if err := json.Unmarshal(rec.Body.Bytes(), &p); err != nil || p.Type != core.ProblemRateLimited || p.Detail != "slow down" {
		t.Fatalf("%v %+v", err, p)
	}
	rec = httptest.NewRecorder()
	WriteProblem(rec, &core.Problem{Type: core.ProblemMalformed})
	if rec.Code != 400 || rec.Header().Get("Retry-After") != "" {
		t.Fatalf("%d %v", rec.Code, rec.Header())
	}
	rec = httptest.NewRecorder()
	WriteError(rec, errors.New("secret internal detail"))
	if rec.Code != 500 || strings.Contains(rec.Body.String(), "secret") {
		t.Fatalf("%d %s", rec.Code, rec.Body)
	}
	rec = httptest.NewRecorder()
	WriteProblem(rec, nil)
	if rec.Code != 500 {
		t.Fatal(rec.Code)
	}
}

func TestWriteJSON(t *testing.T) {
	rec := httptest.NewRecorder()
	WriteJSON(rec, 201, map[string]int{"a": 1})
	if rec.Code != 201 || rec.Header().Get("Content-Type") != "application/json" || strings.TrimSpace(rec.Body.String()) != `{"a":1}` {
		t.Fatalf("%d %v %s", rec.Code, rec.Header(), rec.Body)
	}
	rec = httptest.NewRecorder()
	WriteJSON(rec, 200, make(chan int))
	if rec.Code != 500 {
		t.Fatal(rec.Code)
	}
}

func TestHealth(t *testing.T) {
	var pingErr error
	h := &Health{Ping: func(context.Context) error { return pingErr }}
	get := func(method string) *httptest.ResponseRecorder {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(method, "/healthz", nil))
		return rec
	}
	if rec := get("GET"); rec.Code != 503 || !strings.Contains(rec.Body.String(), "starting") {
		t.Fatalf("%d %s", rec.Code, rec.Body)
	}
	h.SetReady(true)
	if rec := get("GET"); rec.Code != 200 || !strings.Contains(rec.Body.String(), `"ok"`) {
		t.Fatalf("%d %s", rec.Code, rec.Body)
	}
	if rec := get("HEAD"); rec.Code != 200 || rec.Body.Len() != 0 {
		t.Fatalf("%d", rec.Code)
	}
	pingErr = errors.New("sqlite: disk I/O error /var/lib/x")
	if rec := get("GET"); rec.Code != 503 || strings.Contains(rec.Body.String(), "sqlite") || !strings.Contains(rec.Body.String(), "database") {
		t.Fatalf("%d %s", rec.Code, rec.Body)
	}
	pingErr = nil
	h.SetReady(false)
	if rec := get("GET"); rec.Code != 503 || !strings.Contains(rec.Body.String(), "shutting_down") {
		t.Fatalf("%d %s", rec.Code, rec.Body)
	}
	if rec := get("POST"); rec.Code != 405 {
		t.Fatal(rec.Code)
	}
	// no Ping func: readiness only
	h2 := &Health{}
	h2.SetReady(true)
	rec := httptest.NewRecorder()
	h2.ServeHTTP(rec, httptest.NewRequest("GET", "/healthz", nil))
	if rec.Code != 200 {
		t.Fatal(rec.Code)
	}
}
