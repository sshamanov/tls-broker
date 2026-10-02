package dnsproxy

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
	"time"

	"tls-broker/internal/core"
	"tls-broker/internal/core/coretest"
	"tls-broker/internal/httpx"
	"tls-broker/internal/metrics"
	"tls-broker/internal/names"
	"tls-broker/internal/store"
)

const goodValue = "gfj9Xq-Wz7jbo5ZFFYAj7RRsbFqS5ywCRcPb4Phv0kE" // 43 chars

// storeEngine is a core.DNSEngine that drives FakeDNSEngine and mirrors its
// challenges into the real SQLite store, as the real engine owns the rows.
type storeEngine struct {
	*coretest.FakeDNSEngine
	st core.ChallengeStore
}

func (e *storeEngine) Present(ctx context.Context, owner, record, value string) (string, error) {
	id, err := e.FakeDNSEngine.Present(ctx, owner, record, value)
	if err != nil {
		return "", err
	}
	if _, gerr := e.st.Get(ctx, id); errors.Is(gerr, core.ErrNotFound) {
		for _, c := range e.FakeDNSEngine.Challenges() {
			if c.ID == id {
				c := c
				if err := e.st.Create(ctx, &c); err != nil {
					return "", err
				}
			}
		}
	}
	return id, nil
}

func (e *storeEngine) Cleanup(ctx context.Context, id string) error {
	if err := e.FakeDNSEngine.Cleanup(ctx, id); err != nil {
		return err
	}
	return e.st.SetState(ctx, id, core.ChallengeDone, "", time.Now())
}

type rec struct {
	metrics.Nop
	requests []metrics.Outcome
}

func (r *rec) Request(_ core.Mode, o metrics.Outcome) { r.requests = append(r.requests, o) }

type env struct {
	t     *testing.T
	h     *Handler
	srv   http.Handler
	gate  *coretest.FakeGate
	eng   *storeEngine
	clock *coretest.FakeClock
	aud   *coretest.FakeAuditor
	st    core.ChallengeStore
	m     *rec
}

func newEnv(t *testing.T, mut ...func(*Options)) *env {
	t.Helper()
	db, err := store.Open(t.TempDir() + "/db.sqlite")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	clock := coretest.NewFakeClock()
	zones, _ := names.NewZones("example.com")
	e := &env{t: t, gate: coretest.NewFakeGate(), clock: clock, aud: coretest.NewFakeAuditor(clock), st: db.Challenges(), m: &rec{}}
	e.eng = &storeEngine{FakeDNSEngine: coretest.NewFakeDNSEngine(nil, clock), st: e.st}
	o := Options{Gate: e.gate, Engine: e.eng, Challenges: e.st, Auditor: e.aud, Metrics: e.m, Clock: clock, Zones: zones,
		Config: core.DNSProxyConfig{PresentTimeout: time.Minute, ChallengeTTL: time.Hour,
			MaxPerSource: core.Limit{Count: 3, Window: time.Hour}}}
	for _, f := range mut {
		f(&o)
	}
	e.h = New(o)
	e.srv = httpx.RealIP(httpx.NewResolver(httpx.Options{}))(e.h)
	return e
}

func (e *env) do(method, path, ip, body string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	req.RemoteAddr = ip + ":4000"
	w := httptest.NewRecorder()
	e.srv.ServeHTTP(w, req)
	return w
}

func (e *env) present(ip, ident, value string) *httptest.ResponseRecorder {
	b, _ := json.Marshal(presentRequest{Identifier: ident, Value: value})
	return e.do("POST", "/dns/present", ip, string(b))
}

func (e *env) mustPresent(ip, ident, value string) presentResponse {
	e.t.Helper()
	w := e.present(ip, ident, value)
	if w.Code != 201 {
		e.t.Fatalf("present: %d %s", w.Code, w.Body)
	}
	var r presentResponse
	if err := json.Unmarshal(w.Body.Bytes(), &r); err != nil {
		e.t.Fatal(err)
	}
	return r
}

func problem(t *testing.T, w *httptest.ResponseRecorder) core.Problem {
	t.Helper()
	if ct := w.Header().Get("Content-Type"); ct != core.ProblemContentType {
		t.Fatalf("content type %q, body %s", ct, w.Body)
	}
	var p core.Problem
	if err := json.Unmarshal(w.Body.Bytes(), &p); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestPresentOK(t *testing.T) {
	e := newEnv(t)
	e.gate.Decide(core.Decision{Allowed: true, Reason: core.ReasonIPGrant, GrantID: 7})
	r := e.mustPresent("10.0.0.5", "Foo.Example.COM", goodValue)
	if r.Record != "_acme-challenge.foo.example.com" || r.Value != goodValue || r.ChallengeID == "" {
		t.Fatalf("response %+v", r)
	}
	c := e.gate.Calls()
	if len(c) != 1 || c[0].Mode != core.ModeDNSProxy || c[0].Source != netip.MustParseAddr("10.0.0.5") || c[0].Names.Key() != "foo.example.com" {
		t.Fatalf("gate calls %+v", c)
	}
	ch := e.eng.Challenges()
	if len(ch) != 1 || ch[0].Owner != "dnsproxy:10.0.0.5" {
		t.Fatalf("challenges %+v", ch)
	}
	ev := e.aud.OfType(core.AuditDNSPresent)
	if len(ev) != 1 || ev[0].Mode != core.ModeDNSProxy || ev[0].Decision != "allow" || ev[0].Reason != core.ReasonIPGrant ||
		ev[0].GrantID != 7 || ev[0].Result != "ok" || ev[0].SourceIP != "10.0.0.5" || !strings.Contains(ev[0].Detail, r.ChallengeID) {
		t.Fatalf("audit %+v", ev)
	}
	if len(e.m.requests) != 1 || e.m.requests[0] != metrics.OutcomeOK {
		t.Fatalf("metrics %v", e.m.requests)
	}
}

func TestPresentWildcardUsesBaseRecord(t *testing.T) {
	e := newEnv(t)
	r := e.mustPresent("10.0.0.5", "*.example.com", goodValue)
	if r.Record != "_acme-challenge.example.com" {
		t.Fatalf("record %q", r.Record)
	}
	if k := e.gate.Calls()[0].Names.Key(); k != "*.example.com" {
		t.Fatalf("gate saw %q", k)
	}
}

func TestPresentDenied(t *testing.T) {
	for _, reason := range []string{core.ReasonWildcardGrantRequired, core.ReasonWildcardUnprotected, core.ReasonDNSMismatch, core.ReasonDNSFailure} {
		t.Run(reason, func(t *testing.T) {
			e := newEnv(t)
			e.gate.Decide(core.Decision{Reason: reason})
			w := e.present("10.0.0.5", "foo.example.com", goodValue)
			if w.Code != 403 {
				t.Fatalf("status %d", w.Code)
			}
			if p := problem(t, w); !strings.Contains(p.Detail, reason) {
				t.Fatalf("detail %q", p.Detail)
			}
			if p, _, _ := e.eng.Calls(); p != 0 {
				t.Fatal("engine called after denial")
			}
			ev := e.aud.OfType(core.AuditDNSPresent)
			if len(ev) != 1 || ev[0].Decision != "deny" || ev[0].Reason != reason || ev[0].Result != "denied" {
				t.Fatalf("audit %+v", ev)
			}
			if e.m.requests[0] != metrics.OutcomeDenied {
				t.Fatalf("metrics %v", e.m.requests)
			}
		})
	}
}

func TestPresentGateError(t *testing.T) {
	e := newEnv(t)
	e.gate.DecideFunc(func(core.Mode, netip.Addr, names.Set) (core.Decision, error) {
		return core.Decision{}, errors.New("db down")
	})
	w := e.present("10.0.0.5", "foo.example.com", goodValue)
	if w.Code != 503 || w.Header().Get("Retry-After") == "" {
		t.Fatalf("status %d %v", w.Code, w.Header())
	}
}

func TestPresentOutsideZone(t *testing.T) {
	e := newEnv(t)
	for _, id := range []string{"foo.other.org", "*.other.org", "example.com.evil.org"} {
		w := e.present("10.0.0.5", id, goodValue)
		if w.Code != 404 {
			t.Fatalf("%s: %d", id, w.Code)
		}
		problem(t, w)
	}
	if len(e.gate.Calls()) != 0 {
		t.Fatal("gate consulted for outside zone")
	}
	if ev := e.aud.OfType(core.AuditDNSPresent); len(ev) != 3 || ev[0].Reason != core.ReasonOutsideManagedZone {
		t.Fatalf("audit %+v", ev)
	}
}

func TestPresentBadInput(t *testing.T) {
	e := newEnv(t)
	long := strings.Repeat("a", 256)
	cases := map[string]string{
		"not json":      `nope`,
		"empty":         ``,
		"unknown field": `{"identifier":"foo.example.com","value":"abc","x":1}`,
		"trailing":      `{"identifier":"foo.example.com","value":"abc"} {}`,
		"no identifier": `{"value":"abc"}`,
		"bad ident":     `{"identifier":"foo..example.com","value":"abc"}`,
		"ip ident":      `{"identifier":"10.0.0.1","value":"abc"}`,
		"no value":      `{"identifier":"foo.example.com"}`,
		"space":         `{"identifier":"foo.example.com","value":"a b"}`,
		"quote":         `{"identifier":"foo.example.com","value":"a\"b"}`,
		"control":       `{"identifier":"foo.example.com","value":"a\nb"}`,
		"non ascii":     `{"identifier":"foo.example.com","value":"aé"}`,
		"too long":      `{"identifier":"foo.example.com","value":"` + long + `"}`,
	}
	for name, body := range cases {
		w := e.do("POST", "/dns/present", "10.0.0.5", body)
		if w.Code != 400 {
			t.Errorf("%s: status %d %s", name, w.Code, w.Body)
			continue
		}
		problem(t, w)
	}
	if p, _, _ := e.eng.Calls(); p != 0 || len(e.gate.Calls()) != 0 {
		t.Fatal("backend reached with bad input")
	}
	// Any printable value up to 255 characters is accepted.
	if w := e.present("10.0.0.5", "foo.example.com", strings.Repeat("x", 255)); w.Code != 201 {
		t.Fatalf("255 chars: %d %s", w.Code, w.Body)
	}
}

func TestBodyTooLarge(t *testing.T) {
	e := newEnv(t)
	body := `{"identifier":"foo.example.com","value":"` + strings.Repeat("a", 8192) + `"}`
	if w := e.do("POST", "/dns/present", "10.0.0.5", body); w.Code != 413 {
		t.Fatalf("known length: %d", w.Code)
	}
	req := httptest.NewRequest("POST", "/dns/present", strings.NewReader(body))
	req.ContentLength = -1
	req.RemoteAddr = "10.0.0.5:1"
	w := httptest.NewRecorder()
	e.srv.ServeHTTP(w, req)
	if w.Code != 413 {
		t.Fatalf("unknown length: %d", w.Code)
	}
}

func TestNoIPv4Source(t *testing.T) {
	e := newEnv(t)
	req := httptest.NewRequest("POST", "/dns/present", strings.NewReader(`{"identifier":"foo.example.com","value":"abc"}`))
	req.RemoteAddr = "[2001:db8::1]:1"
	w := httptest.NewRecorder()
	e.srv.ServeHTTP(w, req)
	if w.Code != 403 || !strings.Contains(problem(t, w).Detail, core.ReasonNotIPv4) {
		t.Fatalf("%d %s", w.Code, w.Body)
	}
	if len(e.gate.Calls()) != 0 {
		t.Fatal("gate called")
	}
}

func TestPresentIdempotent(t *testing.T) {
	e := newEnv(t)
	a := e.mustPresent("10.0.0.5", "foo.example.com", goodValue)
	b := e.mustPresent("10.0.0.5", "FOO.example.com.", goodValue)
	if a.ChallengeID != b.ChallengeID || e.eng.ActiveCount() != 1 {
		t.Fatalf("ids %q %q, active %d", a.ChallengeID, b.ChallengeID, e.eng.ActiveCount())
	}
	// Different value, or different source, is a new challenge.
	c := e.mustPresent("10.0.0.5", "foo.example.com", "other")
	d := e.mustPresent("10.0.0.6", "foo.example.com", goodValue)
	if c.ChallengeID == a.ChallengeID || d.ChallengeID == a.ChallengeID || e.eng.ActiveCount() != 3 {
		t.Fatal("distinct presents merged")
	}
}

func TestLimiter(t *testing.T) {
	e := newEnv(t)
	for _, v := range []string{"v1", "v2", "v3"} {
		e.mustPresent("10.0.0.5", "foo.example.com", v)
		e.clock.Advance(time.Minute)
	}
	// An idempotent repeat is not counted and not refused.
	e.mustPresent("10.0.0.5", "foo.example.com", "v1")
	w := e.present("10.0.0.5", "foo.example.com", "v4")
	if w.Code != 429 {
		t.Fatalf("status %d %s", w.Code, w.Body)
	}
	// First event was 3 minutes ago: 57 minutes remain.
	if ra := w.Header().Get("Retry-After"); ra != "3420" {
		t.Fatalf("Retry-After %q", ra)
	}
	problem(t, w)
	if p, _, _ := e.eng.Calls(); p != 4 { // v1..v3 and the repeat
		t.Fatalf("engine calls %d", p)
	}
	// Another source is unaffected.
	e.mustPresent("10.0.0.6", "foo.example.com", "v4")
	// After the window the first slot frees up.
	e.clock.Advance(57 * time.Minute)
	e.mustPresent("10.0.0.5", "foo.example.com", "v4")
	if w := e.present("10.0.0.5", "foo.example.com", "v5"); w.Code != 429 {
		t.Fatalf("status %d", w.Code)
	}
	if ev := e.aud.OfType(core.AuditDNSPresent); ev[4].Reason != core.ReasonRateLimited || ev[4].Result != "denied" {
		t.Fatalf("audit %+v", ev[4])
	}
	last := e.m.requests[len(e.m.requests)-1]
	if last != metrics.OutcomeRateLimited {
		t.Fatalf("metrics %v", e.m.requests)
	}
}

func TestLimiterDisabled(t *testing.T) {
	e := newEnv(t, func(o *Options) { o.Config.MaxPerSource = core.Limit{} })
	for i := range 10 {
		e.mustPresent("10.0.0.5", "foo.example.com", strings.Repeat("v", i+1))
	}
}

func TestPresentEngineErrors(t *testing.T) {
	cases := []struct {
		name string
		err  error
		code int
	}{
		{"propagation", core.ErrDNSPropagation, 504},
		{"wrapped propagation", errors.Join(errors.New("x"), core.ErrDNSPropagation), 504},
		{"deadline", context.DeadlineExceeded, 504},
		{"route53", errors.New("AccessDenied"), 503},
		{"outside zone", core.ErrOutsideManagedZones, 404},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			e := newEnv(t)
			e.eng.OnPresent(func(context.Context, string, string, string) error { return c.err })
			w := e.present("10.0.0.5", "foo.example.com", goodValue)
			if w.Code != c.code {
				t.Fatalf("status %d %s", w.Code, w.Body)
			}
			if p := problem(t, w); strings.Contains(p.Detail, "AccessDenied") {
				t.Fatalf("leaked error text: %q", p.Detail)
			}
			ev := e.aud.OfType(core.AuditDNSPresent)
			if len(ev) != 1 || ev[0].Result != "failed" || ev[0].Decision != "allow" {
				t.Fatalf("audit %+v", ev)
			}
		})
	}
}

func TestPresentTimeout(t *testing.T) {
	e := newEnv(t, func(o *Options) { o.Config.PresentTimeout = 20 * time.Millisecond })
	e.eng.OnPresent(func(ctx context.Context, _, _, _ string) error { <-ctx.Done(); return ctx.Err() })
	if w := e.present("10.0.0.5", "foo.example.com", goodValue); w.Code != 504 {
		t.Fatalf("status %d", w.Code)
	}
}

func TestCleanup(t *testing.T) {
	e := newEnv(t)
	r := e.mustPresent("10.0.0.5", "foo.example.com", goodValue)
	body := `{"challenge_id":"` + r.ChallengeID + `"}`

	// Another source address may not clean it up.
	if w := e.do("POST", "/dns/cleanup", "10.0.0.6", body); w.Code != 403 {
		t.Fatalf("other source: %d", w.Code)
	} else {
		problem(t, w)
	}
	if e.eng.ActiveCount() != 1 {
		t.Fatal("cleaned by foreign source")
	}
	if w := e.do("DELETE", "/dns/challenges/"+r.ChallengeID, "10.0.0.6", ""); w.Code != 403 {
		t.Fatalf("other source delete: %d", w.Code)
	}

	if w := e.do("POST", "/dns/cleanup", "10.0.0.5", body); w.Code != 204 || w.Body.Len() != 0 {
		t.Fatalf("owner: %d %s", w.Code, w.Body)
	}
	if e.eng.ActiveCount() != 0 {
		t.Fatal("not cleaned")
	}
	// Idempotent, by either route.
	if w := e.do("POST", "/dns/cleanup", "10.0.0.5", body); w.Code != 204 {
		t.Fatalf("repeat: %d", w.Code)
	}
	if w := e.do("DELETE", "/dns/challenges/"+r.ChallengeID, "10.0.0.5", ""); w.Code != 204 {
		t.Fatalf("delete: %d", w.Code)
	}

	ev := e.aud.OfType(core.AuditDNSCleanup)
	if len(ev) != 5 {
		t.Fatalf("audit events %d", len(ev))
	}
	if ev[0].Decision != "deny" || ev[0].Reason != reasonNotOwner || ev[2].Decision != "allow" || ev[2].Result != "ok" ||
		ev[2].Mode != core.ModeDNSProxy || ev[2].Names[0] != "foo.example.com" {
		t.Fatalf("audit %+v", ev)
	}
}

func TestCleanupErrors(t *testing.T) {
	e := newEnv(t)
	if w := e.do("POST", "/dns/cleanup", "10.0.0.5", `{"challenge_id":"nope"}`); w.Code != 404 {
		t.Fatalf("unknown: %d", w.Code)
	}
	if w := e.do("DELETE", "/dns/challenges/nope", "10.0.0.5", ""); w.Code != 404 {
		t.Fatalf("unknown delete: %d", w.Code)
	}
	for _, b := range []string{``, `{}`, `{"challenge_id":""}`, `[1]`, `{"challenge_id":"a","x":1}`} {
		if w := e.do("POST", "/dns/cleanup", "10.0.0.5", b); w.Code != 400 {
			t.Fatalf("%q: %d", b, w.Code)
		}
	}
	if w := e.do("POST", "/dns/cleanup", "10.0.0.5", `{"challenge_id":"`+strings.Repeat("a", 9000)+`"}`); w.Code != 413 {
		t.Fatalf("oversized: %d", w.Code)
	}
	r := e.mustPresent("10.0.0.5", "foo.example.com", goodValue)
	e.eng.OnCleanup(func(context.Context, core.Challenge) error { return errors.New("route53 down") })
	w := e.do("POST", "/dns/cleanup", "10.0.0.5", `{"challenge_id":"`+r.ChallengeID+`"}`)
	if w.Code != 503 || strings.Contains(w.Body.String(), "route53") {
		t.Fatalf("engine error: %d %s", w.Code, w.Body)
	}
}

func TestCleanupDoesNotTouchOrderChallenges(t *testing.T) {
	e := newEnv(t)
	now := e.clock.Now()
	if err := e.st.Create(context.Background(), &core.Challenge{ID: "o1", ZoneID: "Z", RecordName: "_acme-challenge.foo.example.com",
		Value: "v", Owner: core.OrderOwner("abc"), State: core.ChallengeReady, CreatedAt: now}); err != nil {
		t.Fatal(err)
	}
	if w := e.do("POST", "/dns/cleanup", "10.0.0.5", `{"challenge_id":"o1"}`); w.Code != 403 {
		t.Fatalf("status %d", w.Code)
	}
}

func TestList(t *testing.T) {
	e := newEnv(t)
	a := e.mustPresent("10.0.0.5", "foo.example.com", "v1")
	b := e.mustPresent("10.0.0.5", "*.example.com", "v2")
	e.mustPresent("10.0.0.6", "bar.example.com", "v3")
	e.do("POST", "/dns/cleanup", "10.0.0.5", `{"challenge_id":"`+a.ChallengeID+`"}`)

	w := e.do("GET", "/dns/challenges", "10.0.0.5", "")
	if w.Code != 200 {
		t.Fatalf("status %d", w.Code)
	}
	var out struct{ Challenges []challengeView }
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	if len(out.Challenges) != 1 || out.Challenges[0].ChallengeID != b.ChallengeID || out.Challenges[0].State != "ready" ||
		out.Challenges[0].Record != "_acme-challenge.example.com" {
		t.Fatalf("list %+v", out)
	}
	w = e.do("GET", "/dns/challenges", "10.0.0.9", "")
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"challenges":[]`) {
		t.Fatalf("empty list: %d %s", w.Code, w.Body)
	}
}

func TestSweep(t *testing.T) {
	e := newEnv(t, func(o *Options) { o.Config.MaxPerSource = core.Limit{} })
	old := e.mustPresent("10.0.0.5", "foo.example.com", "old")
	e.clock.Advance(40 * time.Minute)
	e.mustPresent("10.0.0.5", "foo.example.com", "young")
	// A broker order's challenge, equally old, is not the proxy's business.
	if err := e.st.Create(context.Background(), &core.Challenge{ID: "ord", ZoneID: "Z", RecordName: "_acme-challenge.x.example.com",
		Value: "v", Owner: core.OrderOwner("abc"), State: core.ChallengeReady, CreatedAt: e.clock.Now().Add(-40 * time.Minute)}); err != nil {
		t.Fatal(err)
	}
	e.clock.Advance(30 * time.Minute) // old is 70 minutes, young 30

	n, err := e.h.Sweep(context.Background())
	if err != nil || n != 1 {
		t.Fatalf("sweep: %d %v", n, err)
	}
	if got := e.eng.Active("_acme-challenge.foo.example.com"); len(got) != 1 || got[0] != "young" {
		t.Fatalf("active %v", got)
	}
	ev := e.aud.OfType(core.AuditDNSCleanup)
	if len(ev) != 1 || ev[0].Result != "ok" || ev[0].SourceIP != "10.0.0.5" || !strings.Contains(ev[0].Detail, old.ChallengeID) {
		t.Fatalf("audit %+v", ev)
	}
	if n, _ := e.h.Sweep(context.Background()); n != 0 {
		t.Fatalf("second sweep cleaned %d", n)
	}
	e.clock.Advance(time.Hour)
	if n, _ := e.h.Sweep(context.Background()); n != 1 {
		t.Fatalf("young not swept: %d", n)
	}
	// The order's challenge is untouched.
	if c, _ := e.st.Get(context.Background(), "ord"); c.State != core.ChallengeReady {
		t.Fatalf("order challenge %s", c.State)
	}
}

func TestSweepErrorKeepsGoing(t *testing.T) {
	e := newEnv(t)
	e.mustPresent("10.0.0.5", "foo.example.com", "a")
	e.mustPresent("10.0.0.6", "foo.example.com", "b")
	e.eng.OnCleanup(func(_ context.Context, c core.Challenge) error {
		if c.Value == "a" {
			return errors.New("boom")
		}
		return nil
	})
	e.clock.Advance(2 * time.Hour)
	n, err := e.h.Sweep(context.Background())
	if n != 1 || err == nil {
		t.Fatalf("sweep %d %v", n, err)
	}
	if ev := e.aud.OfType(core.AuditDNSCleanup); len(ev) != 2 || ev[0].Result != "failed" || ev[1].Result != "ok" {
		t.Fatalf("audit %+v", ev)
	}
}

func TestMethodsAndPaths(t *testing.T) {
	e := newEnv(t)
	if w := e.do("GET", "/dns/present", "10.0.0.5", ""); w.Code != 405 {
		t.Fatalf("GET present: %d", w.Code)
	}
	if w := e.do("POST", "/dns/nothing", "10.0.0.5", ""); w.Code != 404 {
		t.Fatalf("unknown path: %d", w.Code)
	}
}
