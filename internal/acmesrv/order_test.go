package acmesrv

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"io"
	"net/http"
	"net/netip"
	"strings"
	"testing"
	"time"

	"tls-broker/internal/core"
	"tls-broker/internal/core/coretest"
	"tls-broker/internal/names"
)

func smallRSAKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	k, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func ids(vals ...string) []identifierObj {
	var out []identifierObj
	for _, v := range vals {
		typ := "dns"
		if t, v2, ok := strings.Cut(v, ":"); ok {
			typ, v = t, v2
		}
		out = append(out, identifierObj{Type: typ, Value: v})
	}
	return out
}

func TestNewOrderRejectedIdentifiers(t *testing.T) {
	e := newEnv(t)
	c := e.newRaw(coretest.GenKey()).register()
	post := func(v ...string) *response {
		return c.post(e.url(pathNewOrder), map[string]any{"identifiers": ids(v...)})
	}
	p := expectProblem(t, post("a.example.com", "x.other.net", "ip:10.0.0.1", "bad..name.example.com"), 400, core.ProblemRejectedIdentifier)
	if len(p.Subproblems) != 3 {
		t.Fatalf("subproblems %+v", p.Subproblems)
	}
	types := map[string]string{}
	for _, s := range p.Subproblems {
		types[s.Identifier.Value] = s.Type
	}
	if types["x.other.net"] != core.ProblemRejectedIdentifier || types["10.0.0.1"] != core.ProblemUnsupportedIdentifier ||
		types["bad..name.example.com"] != core.ProblemRejectedIdentifier {
		t.Fatalf("subproblem types %v", types)
	}
	expectProblem(t, post("ip:10.0.0.1"), 400, core.ProblemUnsupportedIdentifier)
	expectProblem(t, c.post(e.url(pathNewOrder), map[string]any{"identifiers": []identifierObj{}}), 400, core.ProblemMalformed)
	expectProblem(t, c.post(e.url(pathNewOrder), nil), 400, core.ProblemMalformed)
	r := c.post(e.url(pathNewOrder), map[string]any{"identifiers": ids("a.example.com"), "notAfter": "2030-01-01T00:00:00Z"})
	expectProblem(t, r, 400, core.ProblemMalformed)

	if len(e.iss.Admits()) != 0 || len(e.gate.Calls()) != 0 {
		t.Fatal("rejected identifiers reached the gate or issuer")
	}
	evs := e.aud.OfType(core.AuditGate)
	if len(evs) < 1 || evs[0].Decision != core.AuditDecisionDeny {
		t.Fatalf("audit %+v", evs)
	}
	// Only outside-zone names: reason outside_managed_zone.
	expectProblem(t, post("x.other.net"), 400, core.ProblemRejectedIdentifier)
	evs = e.aud.OfType(core.AuditGate)
	if last := evs[len(evs)-1]; last.Reason != core.ReasonOutsideManagedZone {
		t.Fatalf("last audit %+v", last)
	}
}

func TestNewOrderGateDenied(t *testing.T) {
	e := newEnv(t)
	c := e.newRaw(coretest.GenKey()).register()
	e.gate.Decide(core.Decision{Reason: core.ReasonDNSMismatch, Name: "www.example.com", Detail: "resolves to 192.0.2.7"})
	r := c.post(e.url(pathNewOrder), map[string]any{"identifiers": ids("www.example.com", "Example.COM.")})
	p := expectProblem(t, r, 403, core.ProblemUnauthorized)
	if !strings.Contains(p.Detail, "dns_mismatch") || !strings.Contains(p.Detail, "127.0.0.1") || !strings.Contains(p.Detail, "192.0.2.7") {
		t.Fatalf("detail %q", p.Detail)
	}
	if len(p.Subproblems) != 1 || p.Subproblems[0].Identifier.Value != "www.example.com" {
		t.Fatalf("subproblems %+v", p.Subproblems)
	}
	calls := e.gate.Calls()
	if len(calls) != 1 || calls[0].Mode != core.ModeACME || calls[0].Names.Key() != "example.com,www.example.com" ||
		calls[0].Source != netip.MustParseAddr("127.0.0.1") {
		t.Fatalf("gate calls %+v", calls)
	}
	if len(e.iss.Admits()) != 0 {
		t.Fatal("denied order reached the issuer")
	}
	evs := e.aud.OfType(core.AuditGate)
	if len(evs) != 1 || evs[0].Reason != core.ReasonDNSMismatch || evs[0].SourceIP != "127.0.0.1" || evs[0].Mode != core.ModeACME {
		t.Fatalf("audit %+v", evs)
	}
	// A resolver failure's detail (the DoH client's error text) stays in the
	// audit log and is not shown to the client.
	e.gate.Decide(core.Decision{Reason: core.ReasonDNSFailure, Name: "www.example.com",
		Detail: `Get "https://cloudflare-dns.com/dns-query": dial tcp 1.1.1.1:443: i/o timeout`})
	p = expectProblem(t, c.post(e.url(pathNewOrder), map[string]any{"identifiers": ids("www.example.com")}), 403, core.ProblemUnauthorized)
	if !strings.Contains(p.Detail, "dns_failure") || strings.Contains(p.Detail, "cloudflare") || strings.Contains(p.Detail, "1.1.1.1") {
		t.Fatalf("resolver error leaked: %q", p.Detail)
	}
	if evs := e.aud.OfType(core.AuditGate); len(evs) != 2 || !strings.Contains(evs[1].Detail, "1.1.1.1") {
		t.Fatalf("resolver error not audited: %+v", evs)
	}
	// Allowed orders are not audited here: the issuer records them.
	e.gate.Decide(core.Decision{Allowed: true, Reason: core.ReasonIPGrant, GrantID: 7})
	o, _ := c.newOrder("www.example.com")
	if o.Status != "ready" || e.iss.Admits()[0].Decision.GrantID != 7 || len(e.aud.Events()) != 2 {
		t.Fatalf("allowed: %+v %d events", o, len(e.aud.Events()))
	}
}

func TestNewOrderProviderDown(t *testing.T) {
	e := newEnv(t)
	c := e.newRaw(coretest.GenKey()).register()
	e.iss.setAdmitErr(&core.AdmissionError{Kind: core.AdmissionProviderDown, RetryAfter: 5 * time.Minute, Reason: "all down"})
	r := c.post(e.url(pathNewOrder), map[string]any{"identifiers": ids("a.example.com")})
	expectProblem(t, r, 503, core.ProblemServerInternal)
	if r.Header.Get("Retry-After") != "300" {
		t.Fatalf("Retry-After %q", r.Header.Get("Retry-After"))
	}
	if evs := e.aud.OfType(core.AuditOrder); len(evs) != 0 {
		t.Fatalf("refusal audited twice (the issuer audits it): %+v", evs)
	}
	e.iss.setAdmitErr(&core.AdmissionError{Kind: core.AdmissionBusy, RetryAfter: 30 * time.Second})
	r = c.post(e.url(pathNewOrder), map[string]any{"identifiers": ids("a.example.com")})
	expectProblem(t, r, 429, core.ProblemRateLimited)
	if r.Header.Get("Retry-After") != "30" {
		t.Fatalf("Retry-After %q", r.Header.Get("Retry-After"))
	}
}

func TestOrderAccessControl(t *testing.T) {
	e := newEnv(t)
	a := e.newRaw(coretest.GenKey()).register()
	b := e.newRaw(coretest.GenKey()).register()
	o, loc := a.newOrder("a.example.com")
	csr := coretest.MakeCSR(coretest.GenKey(), "a.example.com")

	expectProblem(t, b.post(loc, nil), 404, core.ProblemMalformed)
	expectProblem(t, b.post(o.Authorizations[0], nil), 404, core.ProblemMalformed)
	expectProblem(t, b.post(o.Finalize, csrPayload(csr)), 404, core.ProblemMalformed)
	if len(e.iss.Finalizes()) != 0 {
		t.Fatal("foreign finalize reached the issuer")
	}
	r := a.post(o.Finalize, csrPayload(csr))
	var fin orderObj
	_ = json.Unmarshal(r.body, &fin)
	if r.StatusCode != http.StatusOK || fin.Status != "valid" || fin.Certificate == "" {
		t.Fatalf("finalize %d %s", r.StatusCode, r.body)
	}
	expectProblem(t, b.post(fin.Certificate, nil), 404, core.ProblemMalformed)
	r = a.post(fin.Certificate, nil)
	if r.StatusCode != http.StatusOK || r.Header.Get("Content-Type") != "application/pem-certificate-chain" {
		t.Fatalf("cert %d %q", r.StatusCode, r.Header.Get("Content-Type"))
	}
	if chain, err := coretest.ParseChain(r.body); err != nil || len(chain) != 2 {
		t.Fatalf("chain %v", err)
	}
	// Certbot 0.31 sends the certificate POST-as-GET with Content-Type
	// application/pkix-cert (seen in make compat). That is accepted for
	// the certificate resource only.
	r = a.send(fin.Certificate, signJWS(a.key, a.header(fin.Certificate), encodePayload(nil)), "application/pkix-cert")
	if r.StatusCode != http.StatusOK || r.Header.Get("Content-Type") != "application/pem-certificate-chain" {
		t.Fatalf("cert with certbot 0.31 content type: %d %s", r.StatusCode, r.body)
	}
	expectProblem(t, a.send(loc, signJWS(a.key, a.header(loc), encodePayload(nil)), "application/pkix-cert"), 415, core.ProblemMalformed)
	// Unknown resources.
	expectProblem(t, a.post(e.url(pathOrder+"nope"), nil), 404, core.ProblemMalformed)
	expectProblem(t, a.post(e.url(pathAuthz+fin.Finalize[len(e.url(pathOrder)):len(e.url(pathOrder))+22]+"/5"), nil), 404, core.ProblemMalformed)
	expectProblem(t, a.post(e.url(pathCert+"nope"), nil), 404, core.ProblemMalformed)
}

func TestAuthorizationAndChallenge(t *testing.T) {
	e := newEnv(t)
	c := e.newRaw(coretest.GenKey()).register()
	o, _ := c.newOrder("*.example.org", "example.org")
	var az authzObj
	r := c.post(o.Authorizations[0], nil)
	_ = json.Unmarshal(r.body, &az)
	// Set order: "*.example.org" sorts first.
	if az.Status != "valid" || !az.Wildcard || az.Identifier.Value != "example.org" || len(az.Challenges) != 1 {
		t.Fatalf("authz %s", r.body)
	}
	ch := az.Challenges[0]
	if ch.Type != "dns-01" || ch.Status != "valid" || len(ch.Token) < 22 || ch.Validated == "" {
		t.Fatalf("challenge %+v", ch)
	}
	if _, err := time.Parse(time.RFC3339, ch.Validated); err != nil {
		t.Fatal(err)
	}
	// Responding to the challenge and fetching it give the same valid object.
	for _, payload := range []any{map[string]any{}, nil} {
		r = c.post(ch.URL, payload)
		var got challengeObj
		_ = json.Unmarshal(r.body, &got)
		if r.StatusCode != http.StatusOK || got != ch || !strings.Contains(r.Header.Values("Link")[1], `rel="up"`) {
			t.Fatalf("challenge post: %d %s %v", r.StatusCode, r.body, r.Header.Values("Link"))
		}
	}
	r = c.post(o.Authorizations[1], map[string]any{"status": "deactivated"})
	if r.StatusCode != http.StatusOK || !strings.Contains(string(r.body), `"status":"deactivated"`) {
		t.Fatalf("deactivate: %d %s", r.StatusCode, r.body)
	}
	expectProblem(t, c.post(o.Authorizations[1], map[string]any{"status": "valid"}), 400, core.ProblemMalformed)
}

func TestFinalizeErrors(t *testing.T) {
	e := newEnv(t)
	e.iss.setFinalizeValid(false)
	c := e.newRaw(coretest.GenKey()).register()
	o, _ := c.newOrder("a.example.com")

	expectProblem(t, c.post(o.Finalize, map[string]string{"csr": "!!!"}), 400, core.ProblemBadCSR)
	expectProblem(t, c.post(o.Finalize, map[string]string{"csr": "AAAA"}), 400, core.ProblemBadCSR)
	expectProblem(t, c.post(o.Finalize, nil), 400, core.ProblemMalformed)
	// Names that do not match the order: the issuer's badCSR.
	expectProblem(t, c.post(o.Finalize, csrPayload(coretest.MakeCSR(coretest.GenKey(), "b.example.com"))), 400, core.ProblemBadCSR)

	// Gate re-check at finalize.
	e.gate.Decide(core.Decision{Reason: core.ReasonDNSMismatch, Name: "a.example.com"})
	expectProblem(t, c.post(o.Finalize, csrPayload(coretest.MakeCSR(coretest.GenKey(), "a.example.com"))), 403, core.ProblemUnauthorized)
	e.gate.DecideFunc(nil)

	before := len(e.gate.Calls())
	if r := c.post(o.Finalize, csrPayload(coretest.MakeCSR(coretest.GenKey(), "a.example.com"))); r.StatusCode != http.StatusOK {
		t.Fatalf("finalize %d %s", r.StatusCode, r.body)
	}
	// The server asks the gate once and hands the decision to the issuer, so
	// the issuer does not ask again.
	if len(e.gate.Calls()) != before+1 {
		t.Fatalf("gate asked %d times for one finalize", len(e.gate.Calls())-before)
	}
	if fin := e.iss.Finalizes(); len(fin) == 0 || !fin[len(fin)-1].Decision.Allowed {
		t.Fatalf("finalize request without the gate decision: %+v", fin)
	}
	// A different CSR after the first: badCSR, gate not asked again.
	calls := len(e.gate.Calls())
	expectProblem(t, c.post(o.Finalize, csrPayload(coretest.MakeCSR(coretest.GenKey(), "a.example.com"))), 400, core.ProblemBadCSR)
	if len(e.gate.Calls()) != calls {
		t.Fatal("gate re-asked for a processing order")
	}
	if evs := e.aud.OfType(core.AuditOrder); len(evs) < 3 {
		t.Fatalf("finalize refusals audited: %+v", evs)
	}

	// An order past its TTL: invalid when polled, orderNotReady at finalize.
	o2, loc2 := c.newOrder("b.example.com")
	e.clock.Advance(e.cfg.Current().Scheduler.OrderTTL + time.Second)
	r := c.post(loc2, nil)
	if !strings.Contains(string(r.body), `"status":"invalid"`) {
		t.Fatalf("expired poll %s", r.body)
	}
	expectProblem(t, c.post(o2.Finalize, csrPayload(coretest.MakeCSR(coretest.GenKey(), "b.example.com"))), 403, core.ProblemOrderNotReady)
}

func TestReuseOpenOrder(t *testing.T) {
	e := newEnv(t)
	c := e.newRaw(coretest.GenKey()).register()
	_, loc1 := c.newOrder("a.example.com", "b.example.com")
	_, loc2 := c.newOrder("B.example.com", "a.example.com")
	if loc1 != loc2 {
		t.Fatalf("open order not reused: %s vs %s", loc1, loc2)
	}
	set := e.iss.Admits()[1].Names
	if !set.Equal(names.MustSet("a.example.com", "b.example.com")) {
		t.Fatalf("names %v", set)
	}
}

func TestRenewalInfoErrors(t *testing.T) {
	e := newEnv(t)
	get := func(p string) *response {
		resp, err := e.httpClient().Get(e.url(p))
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		return &response{Response: resp, body: b}
	}
	expectProblem(t, get(pathRenewalInfo+"/AAAA.BBBB"), 404, core.ProblemMalformed)
	expectProblem(t, get(pathRenewalInfo+"/not-a-cert-id"), 400, core.ProblemMalformed)
	expectProblem(t, get(pathRenewalInfo+"/AA!A.BB"), 400, core.ProblemMalformed)
}
