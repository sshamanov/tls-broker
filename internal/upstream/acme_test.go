package upstream

import (
	"bytes"
	"context"
	"crypto"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"net/http"
	"slices"
	"strings"
	"testing"
	"time"

	"tls-broker/internal/core"
	"tls-broker/internal/core/coretest"
	"tls-broker/internal/names"
)

type fixture struct {
	ca      *stubCA
	secrets *coretest.FakeSecrets
	clock   *stepClock
	p       *ACMEProvider
}

func newFixture(t *testing.T, mod ...func(*core.ProviderConfig, *core.UpstreamConfig)) *fixture {
	t.Helper()
	f := &fixture{ca: newStubCA(t), secrets: coretest.NewFakeSecrets(), clock: newStepClock()}
	f.p = f.provider(t, mod...)
	return f
}

func (f *fixture) provider(t *testing.T, mod ...func(*core.ProviderConfig, *core.UpstreamConfig)) *ACMEProvider {
	t.Helper()
	cfg := core.ProviderConfig{Name: "stub", DirectoryURL: f.ca.dirURL(), Contact: "ops@example.com", ARI: true, ARIExempt: true,
		CAAIssuers: []string{"stub.test"}, AccountURIHonoured: true}
	up := core.DefaultConfig().Upstream
	up.HTTPTimeout = 5 * time.Second
	for _, m := range mod {
		m(&cfg, &up)
	}
	p, err := NewACMEProvider(cfg, up, Options{Secrets: f.secrets, Clock: f.clock, RootCAs: f.ca.roots(), UserAgent: "tls-broker/test"})
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func wantKind(t *testing.T, err error, kind core.ProviderErrorKind) *core.ProviderError {
	t.Helper()
	pe := core.AsProviderError(err)
	if pe == nil {
		t.Fatalf("error %v (%T) is not a *core.ProviderError", err, err)
	}
	if pe.Kind != kind {
		t.Fatalf("kind = %s, want %s (%v)", pe.Kind, kind, err)
	}
	if pe.Provider != "stub" {
		t.Fatalf("provider = %q", pe.Provider)
	}
	return pe
}

// issue runs order -> challenges -> accept -> ready for the names.
func (f *fixture) ready(t *testing.T, ctx context.Context, orderNames ...string) core.UpstreamOrder {
	t.Helper()
	o, err := f.p.NewOrder(ctx, orderNames, "")
	if err != nil {
		t.Fatal(err)
	}
	chs, err := f.p.DNSChallenges(ctx, o)
	if err != nil {
		t.Fatal(err)
	}
	for _, ch := range chs {
		if err := f.p.Accept(ctx, ch); err != nil {
			t.Fatal(err)
		}
	}
	o, err = f.p.WaitReady(ctx, o.URL)
	if err != nil {
		t.Fatal(err)
	}
	return o
}

func TestFullFlow(t *testing.T) {
	f := newFixture(t)
	ctx := ctxT(t)

	acct, err := f.p.AccountURL(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(acct, f.ca.url("/acct/")) {
		t.Fatalf("account URL %q", acct)
	}
	again, err := f.p.AccountURL(ctx)
	if err != nil || again != acct {
		t.Fatalf("second AccountURL = %q, %v", again, err)
	}
	if n := f.ca.count("POST /new-acct"); n != 1 {
		t.Fatalf("newAccount requests = %d, want 1", n)
	}
	var contact []string
	acct0 := get(f.ca, func() map[string]json.RawMessage { return f.ca.newAccounts[0] })
	_ = json.Unmarshal(acct0["contact"], &contact)
	if !slices.Equal(contact, []string{"mailto:ops@example.com"}) {
		t.Fatalf("contact = %v", contact)
	}
	if string(acct0["termsOfServiceAgreed"]) != "true" {
		t.Fatalf("terms not agreed: %s", acct0["termsOfServiceAgreed"])
	}

	o, err := f.p.NewOrder(ctx, []string{"*.example.com", "example.com", "www.example.com"}, "")
	if err != nil {
		t.Fatal(err)
	}
	if o.Status != core.UpstreamPending || !strings.HasPrefix(o.URL, f.ca.url("/order/")) || len(o.AuthorizationURLs) != 3 ||
		o.FinalizeURL == "" || o.Expires.IsZero() {
		t.Fatalf("order = %+v", o)
	}
	if !slices.Equal(o.Names, []string{"*.example.com", "example.com", "www.example.com"}) {
		t.Fatalf("names = %v", o.Names)
	}
	got, err := f.p.GetOrder(ctx, o.URL)
	if err != nil || got.URL != o.URL || got.Status != core.UpstreamPending {
		t.Fatalf("GetOrder = %+v, %v", got, err)
	}

	chs, err := f.p.DNSChallenges(ctx, o)
	if err != nil {
		t.Fatal(err)
	}
	if len(chs) != 3 {
		t.Fatalf("challenges = %d, want 3", len(chs))
	}
	if chs[0].Identifier != "example.com" || !chs[0].Wildcard || chs[1].Identifier != "example.com" || chs[1].Wildcard {
		t.Fatalf("wildcard/base challenges = %+v %+v", chs[0], chs[1])
	}
	if chs[0].RecordName != "_acme-challenge.example.com" || chs[1].RecordName != chs[0].RecordName ||
		chs[2].RecordName != names.ChallengeRecord("www.example.com") {
		t.Fatalf("record names = %q %q %q", chs[0].RecordName, chs[1].RecordName, chs[2].RecordName)
	}
	for i, ch := range chs {
		if want := f.ca.keyAuthValue(1, i); ch.Value != want {
			t.Fatalf("challenge %d value = %q, want %q", i, ch.Value, want)
		}
		if ch.AuthorizationURL != o.AuthorizationURLs[i] || ch.URL == "" {
			t.Fatalf("challenge %d = %+v", i, ch)
		}
	}

	// An order without authorization URLs is fetched by URL.
	byURL, err := f.p.DNSChallenges(ctx, core.UpstreamOrder{URL: o.URL})
	if err != nil || len(byURL) != 3 {
		t.Fatalf("DNSChallenges by URL = %d, %v", len(byURL), err)
	}

	for _, ch := range chs {
		if err := f.p.Accept(ctx, ch); err != nil {
			t.Fatal(err)
		}
	}
	// Accepting again is a no-op; the CA sees no second challenge POST.
	posts := f.ca.count("POST /chall/")
	if err := f.p.Accept(ctx, chs[0]); err != nil {
		t.Fatal(err)
	}
	if n := f.ca.count("POST /chall/") - posts; n != 1 { // one POST-as-GET only
		t.Fatalf("repeated Accept made %d requests, want 1 (POST-as-GET)", n)
	}
	rest, err := f.p.DNSChallenges(ctx, o)
	if err != nil || len(rest) != 0 {
		t.Fatalf("challenges after validation = %v, %v", rest, err)
	}

	ready, err := f.p.WaitReady(ctx, o.URL)
	if err != nil || ready.Status != core.UpstreamReady {
		t.Fatalf("WaitReady = %+v, %v", ready, err)
	}

	key := coretest.GenKey()
	csr := coretest.MakeCSR(key, "example.com", "*.example.com", "www.example.com")
	fin, err := f.p.Finalize(ctx, o.URL, csr)
	if err != nil || fin.Status != core.UpstreamValid || fin.CertificateURL == "" {
		t.Fatalf("Finalize = %+v, %v", fin, err)
	}
	again2, err := f.p.Finalize(ctx, o.URL, csr)
	if err != nil || again2.Status != core.UpstreamValid {
		t.Fatalf("repeated Finalize = %+v, %v", again2, err)
	}
	if n := finalizes(f.ca); n != 1 || f.ca.count("POST /order/1/finalize") != 1 {
		t.Fatalf("finalize submissions = %d", n)
	}
	// A different CSR for a finalized order is refused.
	_, err = f.p.Finalize(ctx, o.URL, coretest.MakeCSR(coretest.GenKey(), "example.com", "*.example.com", "www.example.com"))
	pe := wantKind(t, err, core.ProviderRejected)
	if pe.Problem.Type != core.ProblemOrderNotReady {
		t.Fatalf("problem = %v", pe.Problem)
	}

	chain, err := f.p.WaitCertificate(ctx, o.URL)
	if err != nil {
		t.Fatal(err)
	}
	certs, err := coretest.ParseChain(chain)
	if err != nil {
		t.Fatal(err)
	}
	if len(certs) != 2 || !certs[1].Equal(f.ca.inter) || !slices.Contains(certs[0].DNSNames, "*.example.com") {
		t.Fatalf("chain has %d certs; want leaf + intermediate without root", len(certs))
	}
	if !certs[0].PublicKey.(interface{ Equal(crypto.PublicKey) bool }).Equal(key.Public()) {
		t.Fatal("leaf key does not match the CSR")
	}

	id, _ := core.ARICertID(certs[0])
	ri, err := f.p.RenewalInfo(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	if ri.RetryAfter != 6*time.Hour || ri.ExplanationURL != "https://ca.test/why" || ri.WindowEnd.Sub(ri.WindowStart) != 48*time.Hour {
		t.Fatalf("renewal info = %+v", ri)
	}
	if ri.WindowStart.Location() != time.UTC {
		t.Fatal("window not in UTC")
	}

	caps := f.p.Caps()
	if !caps.ARI || !caps.ARIExempt || !caps.AccountURIHonoured || !slices.Equal(caps.CAAIssuers, []string{"stub.test"}) || f.p.Name() != "stub" {
		t.Fatalf("caps = %+v", caps)
	}
}

func TestUserAgentAndHTTPSOnly(t *testing.T) {
	f := newFixture(t)
	var ua string
	f.ca.inject(&stubFault{match: func(r *http.Request) bool { ua = r.UserAgent(); return false }})
	if _, err := f.p.AccountURL(ctxT(t)); err != nil {
		t.Fatal(err)
	}
	ua = get(f.ca, func() string { return ua })
	if !strings.HasPrefix(ua, "tls-broker/test") {
		t.Fatalf("User-Agent = %q", ua)
	}
	_, err := NewACMEProvider(core.ProviderConfig{Name: "x", DirectoryURL: "http://ca.test/dir"}, core.UpstreamConfig{},
		Options{Secrets: coretest.NewFakeSecrets()})
	if err == nil {
		t.Fatal("plain http directory accepted")
	}
	if _, err := NewACMEProvider(core.ProviderConfig{Name: "x", DirectoryURL: "https://ca.test/dir", EABKeyID: "k"}, core.UpstreamConfig{},
		Options{Secrets: coretest.NewFakeSecrets()}); err == nil {
		t.Fatal("EAB key id without secret name accepted")
	}
	p, err := NewACMEProvider(core.ProviderConfig{Name: "x", DirectoryURL: "https://ca.test/dir"}, core.UpstreamConfig{},
		Options{Secrets: coretest.NewFakeSecrets()})
	if err != nil || p.ua != "tls-broker/dev" {
		t.Fatalf("default user agent = %q, %v", p.ua, err)
	}
}

func TestAccountKeyReuse(t *testing.T) {
	f := newFixture(t)
	ctx := ctxT(t)
	u1, err := f.p.AccountURL(ctx)
	if err != nil {
		t.Fatal(err)
	}
	key1, err := f.secrets.Get(ctx, core.SecretProviderAccountKeyPrefix+"stub")
	if err != nil || !bytes.Contains(key1, []byte("BEGIN PRIVATE KEY")) {
		t.Fatalf("stored key = %q, %v", key1, err)
	}
	if stored, _ := f.secrets.Get(ctx, core.SecretProviderAccountURLPrefix+"stub"); string(stored) != u1 {
		t.Fatalf("stored URL = %q", stored)
	}

	// A new instance (restart, registry rebuild) uses the stored URL: no I/O
	// to newAccount, same key.
	p2 := f.provider(t)
	u2, err := p2.AccountURL(ctx)
	if err != nil || u2 != u1 {
		t.Fatalf("second instance URL = %q, %v", u2, err)
	}
	if n := f.ca.count("POST /new-acct"); n != 1 {
		t.Fatalf("newAccount requests = %d", n)
	}
	if _, err := p2.NewOrder(ctx, []string{"a.example.com"}, ""); err != nil {
		t.Fatalf("order with reused account: %v", err)
	}

	// Lost URL: the same key is registered again and the CA returns the
	// existing account.
	if err := f.secrets.Delete(ctx, core.SecretProviderAccountURLPrefix+"stub"); err != nil {
		t.Fatal(err)
	}
	p3 := f.provider(t)
	u3, err := p3.AccountURL(ctx)
	if err != nil || u3 != u1 {
		t.Fatalf("re-registered URL = %q, %v", u3, err)
	}
	key3, _ := f.secrets.Get(ctx, core.SecretProviderAccountKeyPrefix+"stub")
	if !bytes.Equal(key1, key3) {
		t.Fatal("account key was regenerated")
	}
	if n := get(f.ca, func() int { return len(f.ca.accounts) }); n != 1 {
		t.Fatalf("accounts at CA = %d", n)
	}

	// A stored URL from another CA (directory changed) is not used.
	if err := f.secrets.Put(ctx, core.SecretProviderAccountURLPrefix+"stub", []byte("https://other-ca.test/acct/9")); err != nil {
		t.Fatal(err)
	}
	p4 := f.provider(t)
	if u4, err := p4.AccountURL(ctx); err != nil || u4 != u1 {
		t.Fatalf("URL after foreign stored URL = %q, %v", u4, err)
	}

	// A corrupt stored key is an error, never silently replaced.
	if err := f.secrets.Put(ctx, core.SecretProviderAccountKeyPrefix+"stub", []byte("garbage")); err != nil {
		t.Fatal(err)
	}
	_, err = f.provider(t).AccountURL(ctx)
	wantKind(t, err, core.ProviderDown)
	if v, _ := f.secrets.Get(ctx, core.SecretProviderAccountKeyPrefix+"stub"); string(v) != "garbage" {
		t.Fatal("corrupt key was overwritten")
	}
}

func TestImportedKeyFormats(t *testing.T) {
	for _, pemType := range []string{"EC PRIVATE KEY", "RSA PRIVATE KEY"} {
		t.Run(pemType, func(t *testing.T) {
			f := newFixture(t)
			ctx := ctxT(t)
			var raw []byte
			if pemType == "EC PRIVATE KEY" {
				raw = ecPEM(t)
			} else {
				raw = rsaPEM(t)
			}
			if err := f.secrets.Put(ctx, core.SecretProviderAccountKeyPrefix+"stub", raw); err != nil {
				t.Fatal(err)
			}
			if _, err := f.p.AccountURL(ctx); err != nil {
				t.Fatal(err)
			}
			if v, _ := f.secrets.Get(ctx, core.SecretProviderAccountKeyPrefix+"stub"); !bytes.Equal(v, raw) {
				t.Fatal("imported key was replaced")
			}
		})
	}
}

func TestEABRegistration(t *testing.T) {
	mac := []byte("0123456789abcdef0123456789abcdef")
	f := newFixture(t, func(c *core.ProviderConfig, _ *core.UpstreamConfig) {
		c.EABKeyID, c.EABSecretName = "kid-123", "eab-stub"
	})
	f.ca.with(func() { f.ca.eabKeyID, f.ca.eabMAC = "kid-123", mac })
	ctx := ctxT(t)

	// Missing secret: rejected locally, nothing sent.
	_, err := f.p.AccountURL(ctx)
	pe := wantKind(t, err, core.ProviderRejected)
	if sent := get(f.ca, func() int { return f.ca.newAcctSent }); pe.Problem.Type != core.ProblemExternalAccountRequired || sent != 0 {
		t.Fatalf("problem = %v, sent = %d", pe.Problem, sent)
	}

	// The secret as gcloud prints it (base64url) with a trailing newline.
	if err := f.secrets.Put(ctx, "eab-stub", []byte(base64.RawURLEncoding.EncodeToString(mac)+"\n")); err != nil {
		t.Fatal(err)
	}
	if _, err := f.p.AccountURL(ctx); err != nil {
		t.Fatal(err)
	}
	if get(f.ca, func() int { return f.ca.eabVerified }) != 1 {
		t.Fatal("EAB binding was not verified by the CA")
	}

	// Without EAB configured the CA refuses: rejected, problem preserved.
	g := newFixture(t)
	g.ca.with(func() { g.ca.eabKeyID, g.ca.eabMAC = "kid-123", mac })
	_, err = g.p.AccountURL(ctx)
	pe = wantKind(t, err, core.ProviderRejected)
	if pe.Problem.Type != core.ProblemExternalAccountRequired || pe.Problem.Status != 403 {
		t.Fatalf("problem = %+v", pe.Problem)
	}
}

func TestNewOrderPayload(t *testing.T) {
	f := newFixture(t, func(c *core.ProviderConfig, _ *core.UpstreamConfig) { c.Profile = "tlsserver" })
	ctx := ctxT(t)
	if _, err := f.p.NewOrder(ctx, []string{"a.example.com"}, ""); err != nil {
		t.Fatal(err)
	}
	o, err := f.p.NewOrder(ctx, []string{"a.example.com", "b.example.com"}, "aki.serial")
	if err != nil {
		t.Fatal(err)
	}
	if o.Replaces != "aki.serial" {
		t.Fatalf("order replaces = %q", o.Replaces)
	}
	first, second := newOrderReq(f.ca, 0), newOrderReq(f.ca, 1)
	if _, ok := first["replaces"]; ok {
		t.Fatal("empty replaces was sent")
	}
	if string(first["profile"]) != `"tlsserver"` || string(second["profile"]) != `"tlsserver"` {
		t.Fatalf("profile = %s / %s", first["profile"], second["profile"])
	}
	if string(second["replaces"]) != `"aki.serial"` {
		t.Fatalf("replaces = %s", second["replaces"])
	}
	var ids []stubIdent
	_ = json.Unmarshal(second["identifiers"], &ids)
	if len(ids) != 2 || ids[0] != (stubIdent{"dns", "a.example.com"}) {
		t.Fatalf("identifiers = %+v", ids)
	}

	g := newFixture(t)
	if _, err := g.p.NewOrder(ctx, []string{"a.example.com"}, ""); err != nil {
		t.Fatal(err)
	}
	if _, ok := newOrderReq(g.ca, 0)["profile"]; ok {
		t.Fatal("empty profile was sent")
	}
}

func TestAlreadyReplaced(t *testing.T) {
	f := newFixture(t)
	ctx := ctxT(t)
	if _, err := f.p.NewOrder(ctx, []string{"a.example.com"}, "cert-1"); err != nil {
		t.Fatal(err)
	}
	before := f.ca.count("POST /new-order")
	_, err := f.p.NewOrder(ctx, []string{"a.example.com"}, "cert-1")
	pe := wantKind(t, err, core.ProviderAlreadyReplaced)
	if pe.Problem == nil || pe.Problem.Type != core.ProblemAlreadyReplaced || pe.Problem.Status != 409 {
		t.Fatalf("problem = %+v", pe.Problem)
	}
	if pe.AffectsHealth() {
		t.Fatal("alreadyReplaced affects health")
	}
	if n := f.ca.count("POST /new-order") - before; n != 1 {
		t.Fatalf("newOrder requests = %d, want 1 (no silent retry without replaces)", n)
	}
	if n := orders(f.ca); n != 1 {
		t.Fatalf("orders at CA = %d, want 1", n)
	}
	// The engine's retry without replaces works.
	if _, err := f.p.NewOrder(ctx, []string{"a.example.com"}, ""); err != nil {
		t.Fatal(err)
	}
}

func TestReplacesWithoutARI(t *testing.T) {
	f := newFixture(t, func(c *core.ProviderConfig, _ *core.UpstreamConfig) { c.ARI = false })
	ctx := ctxT(t)
	_, err := f.p.NewOrder(ctx, []string{"a.example.com"}, "cert-1")
	wantKind(t, err, core.ProviderRejected)
	_, err = f.p.RenewalInfo(ctx, "cert-1")
	wantKind(t, err, core.ProviderRejected)
	if f.ca.count("POST /new-order") != 0 {
		t.Fatal("order sent")
	}

	g := newFixture(t) // configured with ARI but the CA has no renewalInfo
	g.ca.with(func() { g.ca.noARI = true })
	_, err = g.p.NewOrder(ctx, []string{"a.example.com"}, "cert-1")
	wantKind(t, err, core.ProviderRejected)
	_, err = g.p.RenewalInfo(ctx, "cert-1")
	wantKind(t, err, core.ProviderRejected)
}

func TestRenewalInfoErrors(t *testing.T) {
	f := newFixture(t)
	ctx := ctxT(t)
	_, err := f.p.RenewalInfo(ctx, "unknown.id")
	pe := wantKind(t, err, core.ProviderRejected)
	if pe.Problem.Type != core.ProblemMalformed || pe.Problem.Status != 404 {
		t.Fatalf("problem = %+v", pe.Problem)
	}
	_, err = f.p.RenewalInfo(ctx, "")
	wantKind(t, err, core.ProviderRejected)
	f.ca.inject(&stubFault{match: pathIs("GET", "/renewal-info/"), status: 503, header: map[string]string{"Retry-After": "120"},
		body: `{"type":"urn:ietf:params:acme:error:serverInternal","detail":"busy"}`})
	_, err = f.p.RenewalInfo(ctx, "x.y")
	pe = wantKind(t, err, core.ProviderBusy)
	if pe.RetryAfter != 2*time.Minute {
		t.Fatalf("retry after = %s", pe.RetryAfter)
	}
	// RenewalInfo needs no account.
	if f.ca.count("POST /new-acct") != 0 {
		t.Fatal("RenewalInfo registered an account")
	}
}

func TestBadNonceRetriedTransparently(t *testing.T) {
	f := newFixture(t)
	ctx := ctxT(t)
	if _, err := f.p.AccountURL(ctx); err != nil {
		t.Fatal(err)
	}
	f.ca.with(func() { f.ca.badNonce = 2 })
	o, err := f.p.NewOrder(ctx, []string{"a.example.com"}, "")
	if err != nil {
		t.Fatalf("NewOrder with bad nonces: %v", err)
	}
	if o.URL == "" || orders(f.ca) != 1 || f.ca.count("POST /new-order") != 3 {
		t.Fatalf("orders = %d, requests = %d", orders(f.ca), f.ca.count("POST /new-order"))
	}
}

func TestErrorClasses(t *testing.T) {
	base := time.Date(2026, 10, 2, 12, 0, 0, 0, time.UTC)
	cases := []struct {
		name   string
		status int
		header map[string]string
		body   string
		kind   core.ProviderErrorKind
		retry  time.Duration
		ptype  string
	}{
		{"rateLimited seconds", 429, map[string]string{"Retry-After": "3600"},
			`{"type":"urn:ietf:params:acme:error:rateLimited","detail":"too many new orders","status":429}`,
			core.ProviderRateLimited, time.Hour, core.ProblemRateLimited},
		{"rateLimited http-date", 429, map[string]string{"Retry-After": base.Add(90 * time.Second).Format(http.TimeFormat)},
			`{"type":"urn:ietf:params:acme:error:rateLimited","detail":"slow down"}`,
			core.ProviderRateLimited, 90 * time.Second, core.ProblemRateLimited},
		{"bare 429", 429, nil, `slow down`, core.ProviderRateLimited, 0, ""},
		{"503 with Retry-After", 503, map[string]string{"Retry-After": "30"}, `<html>maintenance</html>`,
			core.ProviderBusy, 30 * time.Second, ""},
		{"serverInternal with Retry-After", 500, map[string]string{"Retry-After": "10"},
			`{"type":"urn:ietf:params:acme:error:serverInternal","detail":"try later"}`,
			core.ProviderBusy, 10 * time.Second, core.ProblemServerInternal},
		{"serverInternal without Retry-After", 500, nil,
			`{"type":"urn:ietf:params:acme:error:serverInternal","detail":"boom"}`, core.ProviderDown, 0, core.ProblemServerInternal},
		{"503 without Retry-After", 503, nil, `unavailable`, core.ProviderDown, 0, ""},
		{"502 html", 502, nil, `<html>bad gateway</html>`, core.ProviderDown, 0, ""},
		{"rejectedIdentifier", 400, nil,
			`{"type":"urn:ietf:params:acme:error:rejectedIdentifier","detail":"policy forbids","status":400,` +
				`"subproblems":[{"type":"urn:ietf:params:acme:error:rejectedIdentifier","detail":"bad name","identifier":{"type":"dns","value":"x.example.com"}}]}`,
			core.ProviderRejected, 0, core.ProblemRejectedIdentifier},
		{"caa", 403, nil, `{"type":"urn:ietf:params:acme:error:caa","detail":"CAA forbids"}`, core.ProviderRejected, 0, core.ProblemCAA},
		{"404 without problem", 404, nil, `not here`, core.ProviderRejected, 0, core.ProblemMalformed},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(t)
			ctx := ctxT(t)
			if _, err := f.p.AccountURL(ctx); err != nil {
				t.Fatal(err)
			}
			f.ca.inject(&stubFault{match: pathIs("POST", "/new-order"), times: 1, status: tc.status, header: tc.header, body: tc.body})
			_, err := f.p.NewOrder(ctx, []string{"x.example.com"}, "")
			pe := wantKind(t, err, tc.kind)
			if pe.RetryAfter != tc.retry {
				t.Fatalf("retry after = %s, want %s", pe.RetryAfter, tc.retry)
			}
			if tc.ptype != "" && (pe.Problem == nil || pe.Problem.Type != tc.ptype) {
				t.Fatalf("problem = %+v, want type %s", pe.Problem, tc.ptype)
			}
			if tc.kind == core.ProviderRejected && tc.ptype == core.ProblemRejectedIdentifier {
				if len(pe.Problem.Subproblems) != 1 || pe.Problem.Subproblems[0].Identifier.Value != "x.example.com" ||
					pe.Problem.Detail != "policy forbids" || pe.Problem.Status != 400 {
					t.Fatalf("problem not preserved: %+v", pe.Problem)
				}
				// The downstream mapping keeps the CA's problem type.
				if p := core.ProblemFromError(err); p.Type != core.ProblemRejectedIdentifier {
					t.Fatalf("downstream problem = %v", p)
				}
			}
			if f.ca.count("POST /new-order") != 1 {
				t.Fatal("provider retried a non-nonce error")
			}
		})
	}
}

func TestTransportErrors(t *testing.T) {
	ctx := ctxT(t)
	t.Run("connection refused", func(t *testing.T) {
		f := newFixture(t)
		f.ca.srv.Close()
		_, err := f.p.AccountURL(ctx)
		pe := wantKind(t, err, core.ProviderDown)
		if pe.Err == nil {
			t.Fatal("no underlying error")
		}
	})
	t.Run("timeout", func(t *testing.T) {
		f := newFixture(t, func(_ *core.ProviderConfig, up *core.UpstreamConfig) { up.HTTPTimeout = 300 * time.Millisecond })
		if _, err := f.p.AccountURL(ctx); err != nil {
			t.Fatal(err)
		}
		f.ca.inject(&stubFault{match: pathIs("POST", "/order/"), delay: 5 * time.Second, status: 200})
		_, err := f.p.GetOrder(ctx, f.ca.url("/order/1"))
		wantKind(t, err, core.ProviderDown)
	})
	t.Run("directory busy", func(t *testing.T) {
		f := newFixture(t)
		f.ca.inject(&stubFault{match: pathIs("GET", "/dir"), times: 1, status: 503, header: map[string]string{"Retry-After": "45"}})
		_, err := f.p.AccountURL(ctx)
		pe := wantKind(t, err, core.ProviderBusy)
		if pe.RetryAfter != 45*time.Second {
			t.Fatalf("retry after = %s", pe.RetryAfter)
		}
		if _, err := f.p.AccountURL(ctx); err != nil {
			t.Fatalf("after the CA recovered: %v", err)
		}
	})
	t.Run("nonce endpoint rate limited", func(t *testing.T) {
		f := newFixture(t)
		f.ca.inject(&stubFault{match: pathIs("HEAD", "/nonce"), status: 429, header: map[string]string{"Retry-After": "60"}})
		_, err := f.p.AccountURL(ctx)
		pe := wantKind(t, err, core.ProviderRateLimited)
		if pe.RetryAfter != time.Minute {
			t.Fatalf("retry after = %s", pe.RetryAfter)
		}
	})
	t.Run("context canceled", func(t *testing.T) {
		f := newFixture(t)
		if _, err := f.p.AccountURL(ctx); err != nil {
			t.Fatal(err)
		}
		f.ca.inject(&stubFault{match: pathIs("POST", "/order/"), delay: 5 * time.Second, status: 200})
		cctx, cancel := context.WithTimeout(ctx, 100*time.Millisecond)
		defer cancel()
		_, err := f.p.GetOrder(cctx, f.ca.url("/order/1"))
		if !errors.Is(err, context.DeadlineExceeded) || core.AsProviderError(err) != nil {
			t.Fatalf("err = %v, want the context error", err)
		}
	})
}

func TestGetOrderUnknown(t *testing.T) {
	f := newFixture(t)
	_, err := f.p.GetOrder(ctxT(t), f.ca.url("/order/99"))
	pe := wantKind(t, err, core.ProviderRejected)
	if pe.Problem.Status != 404 {
		t.Fatalf("problem = %+v", pe.Problem)
	}
}

func TestWaitReadyHonoursRetryAfter(t *testing.T) {
	f := newFixture(t)
	ctx := ctxT(t)
	f.ca.with(func() { f.ca.readyAfter, f.ca.pollRetry = 3, "7" })
	o := f.ready(t, ctx, "a.example.com")
	if o.Status != core.UpstreamReady {
		t.Fatalf("status = %s", o.Status)
	}
	if w := f.clock.Waits(); !slices.Equal(w, []time.Duration{7 * time.Second, 7 * time.Second}) {
		t.Fatalf("waits = %v, want two Retry-After waits of 7s", w)
	}

	g := newFixture(t, func(_ *core.ProviderConfig, up *core.UpstreamConfig) { up.PollInterval = 3 * time.Second })
	g.ca.with(func() { g.ca.readyAfter = 2 })
	g.ready(t, ctx, "a.example.com")
	if w := g.clock.Waits(); !slices.Equal(w, []time.Duration{3 * time.Second}) {
		t.Fatalf("waits = %v, want PollInterval", w)
	}
}

func TestWaitReadyTimeout(t *testing.T) {
	f := newFixture(t, func(_ *core.ProviderConfig, up *core.UpstreamConfig) { up.ValidationTimeout = 10 * time.Second })
	ctx := ctxT(t)
	f.ca.with(func() { f.ca.pollRetry = "4" })
	o, err := f.p.NewOrder(ctx, []string{"a.example.com"}, "")
	if err != nil {
		t.Fatal(err)
	}
	_, err = f.p.WaitReady(ctx, o.URL) // never accepted: stays pending
	wantKind(t, err, core.ProviderDown)
	if w := f.clock.Waits(); !slices.Equal(w, []time.Duration{4 * time.Second, 4 * time.Second, 2 * time.Second}) {
		t.Fatalf("waits = %v, want Retry-After bounded by the timeout", w)
	}
}

func TestValidationFailure(t *testing.T) {
	f := newFixture(t)
	ctx := ctxT(t)
	f.ca.with(func() { f.ca.failValidation = true })
	o, err := f.p.NewOrder(ctx, []string{"a.example.com", "b.example.com"}, "")
	if err != nil {
		t.Fatal(err)
	}
	chs, err := f.p.DNSChallenges(ctx, o)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.p.Accept(ctx, chs[0]); err != nil {
		t.Fatal(err)
	}
	_, err = f.p.WaitReady(ctx, o.URL)
	pe := wantKind(t, err, core.ProviderRejected)
	if pe.Problem.Type != core.ProblemUnauthorized || pe.Problem.Detail != "incorrect TXT record" {
		t.Fatalf("problem = %+v", pe.Problem)
	}
	_, err = f.p.DNSChallenges(ctx, o)
	pe = wantKind(t, err, core.ProviderRejected)
	if pe.Problem.Detail != "incorrect TXT record" {
		t.Fatalf("problem = %+v", pe.Problem)
	}
	_, err = f.p.Finalize(ctx, o.URL, coretest.MakeCSR(coretest.GenKey(), "a.example.com", "b.example.com"))
	wantKind(t, err, core.ProviderRejected)
	_, err = f.p.WaitCertificate(ctx, o.URL)
	wantKind(t, err, core.ProviderRejected)
}

func TestNoDNS01Challenge(t *testing.T) {
	f := newFixture(t)
	f.ca.with(func() { f.ca.noDNS01 = true })
	ctx := ctxT(t)
	o, err := f.p.NewOrder(ctx, []string{"a.example.com"}, "")
	if err != nil {
		t.Fatal(err)
	}
	_, err = f.p.DNSChallenges(ctx, o)
	wantKind(t, err, core.ProviderRejected)
}

func TestFinalizeStates(t *testing.T) {
	f := newFixture(t)
	ctx := ctxT(t)
	key := coretest.GenKey()
	csr := coretest.MakeCSR(key, "a.example.com")

	o, err := f.p.NewOrder(ctx, []string{"a.example.com"}, "")
	if err != nil {
		t.Fatal(err)
	}
	// Pending order: not ready, nothing submitted.
	_, err = f.p.Finalize(ctx, o.URL, csr)
	pe := wantKind(t, err, core.ProviderRejected)
	if pe.Problem.Type != core.ProblemOrderNotReady || finalizes(f.ca) != 0 {
		t.Fatalf("problem = %v, finalizes = %d", pe.Problem, finalizes(f.ca))
	}
	// WaitCertificate on an unfinalized order.
	_, err = f.p.WaitCertificate(ctx, o.URL)
	wantKind(t, err, core.ProviderRejected)
	// Garbage CSR: rejected locally.
	_, err = f.p.Finalize(ctx, o.URL, []byte("nope"))
	pe = wantKind(t, err, core.ProviderRejected)
	if pe.Problem.Type != core.ProblemBadCSR {
		t.Fatalf("problem = %v", pe.Problem)
	}

	// Processing: repeated Finalize returns processing without resubmitting,
	// WaitCertificate polls with Retry-After until valid.
	f.ca.with(func() { f.ca.validAfter, f.ca.pollRetry = 3, "5" })
	o = f.ready(t, ctx, "b.example.com")
	csr = coretest.MakeCSR(key, "b.example.com")
	fin, err := f.p.Finalize(ctx, o.URL, csr)
	if err != nil || fin.Status != core.UpstreamProcessing {
		t.Fatalf("Finalize = %+v, %v", fin, err)
	}
	fin, err = f.p.Finalize(ctx, o.URL, csr)
	if err != nil || fin.Status != core.UpstreamProcessing || finalizes(f.ca) != 1 {
		t.Fatalf("repeated Finalize = %+v, %v, finalizes = %d", fin, err, finalizes(f.ca))
	}
	waitsBefore := len(f.clock.Waits())
	chain, err := f.p.WaitCertificate(ctx, o.URL)
	if err != nil {
		t.Fatal(err)
	}
	if w := f.clock.Waits()[waitsBefore:]; !slices.Equal(w, []time.Duration{5 * time.Second}) {
		t.Fatalf("waits = %v", w)
	}
	if certs, err := coretest.ParseChain(chain); err != nil || len(certs) != 2 {
		t.Fatalf("chain: %d certs, %v", len(certs), err)
	}
	if finalizes(f.ca) != 1 {
		t.Fatalf("finalizes = %d", finalizes(f.ca))
	}
}

func TestFinalizeRaceOrderNotReady(t *testing.T) {
	// An earlier finalize went through but its answer was lost; the CA then
	// says orderNotReady to the repeat. Finalize reports the order's actual
	// state instead of the error.
	f := newFixture(t)
	ctx := ctxT(t)
	o := f.ready(t, ctx, "a.example.com")
	csr := coretest.MakeCSR(coretest.GenKey(), "a.example.com")
	f.ca.inject(&stubFault{times: 1, status: 403,
		body: `{"type":"urn:ietf:params:acme:error:orderNotReady","detail":"order is processing"}`,
		match: func(r *http.Request) bool {
			if r.URL.Path != "/order/1/finalize" {
				return false
			}
			f.ca.orders[1].status = "processing" // called with the stub locked
			return true
		}})
	got, err := f.p.Finalize(ctx, o.URL, csr)
	if err != nil || got.Status != core.UpstreamProcessing {
		t.Fatalf("Finalize after lost answer = %+v, %v", got, err)
	}
}

func TestInvalidOrderOwnError(t *testing.T) {
	f := newFixture(t)
	ctx := ctxT(t)
	o, err := f.p.NewOrder(ctx, []string{"a.example.com"}, "")
	if err != nil {
		t.Fatal(err)
	}
	f.ca.with(func() {
		f.ca.orders[1].status = "invalid"
		f.ca.orders[1].errProblem = map[string]any{"type": "urn:ietf:params:acme:error:caa", "detail": "CAA forbids", "status": 403}
	})
	got, err := f.p.GetOrder(ctx, o.URL)
	if err != nil || got.Status != core.UpstreamInvalid || got.Error == nil || got.Error.Type != core.ProblemCAA {
		t.Fatalf("GetOrder = %+v, %v", got, err)
	}
	_, err = f.p.WaitReady(ctx, o.URL)
	pe := wantKind(t, err, core.ProviderRejected)
	if pe.Problem.Type != core.ProblemCAA {
		t.Fatalf("problem = %+v", pe.Problem)
	}
}

func TestConcurrentFirstUse(t *testing.T) {
	f := newFixture(t)
	ctx := ctxT(t)
	errs := make(chan error, 8)
	for range 8 {
		go func() {
			_, err := f.p.NewOrder(ctx, []string{"a.example.com"}, "")
			errs <- err
		}()
	}
	for range 8 {
		if err := <-errs; err != nil {
			t.Fatal(err)
		}
	}
	if f.ca.count("POST /new-acct") != 1 || orders(f.ca) != 8 {
		t.Fatalf("newAccount = %d, orders = %d", f.ca.count("POST /new-acct"), orders(f.ca))
	}
}

// The adapter behaves like coretest.FakeCA through the interface for the
// states both model: run the same scenario against each.
func TestBehavesLikeFakeCA(t *testing.T) {
	ctx := ctxT(t)
	fake := coretest.NewFakeCA("stub", coretest.NewFakeClock())
	f := newFixture(t)
	for _, p := range []core.Provider{fake, f.p} {
		o, err := p.NewOrder(ctx, []string{"*.example.org", "example.org"}, "")
		if err != nil {
			t.Fatal(err)
		}
		chs, err := p.DNSChallenges(ctx, o)
		if err != nil || len(chs) != 2 || chs[0].RecordName != chs[1].RecordName {
			t.Fatalf("%T: challenges %+v, %v", p, chs, err)
		}
		csr := coretest.MakeCSR(coretest.GenKey(), "example.org", "*.example.org")
		_, err = p.Finalize(ctx, o.URL, csr)
		if pe := core.AsProviderError(err); pe == nil || pe.Kind != core.ProviderRejected || pe.Problem.Type != core.ProblemOrderNotReady {
			t.Fatalf("%T: finalize pending = %v", p, err)
		}
		for _, ch := range chs {
			if err := p.Accept(ctx, ch); err != nil {
				t.Fatal(err)
			}
		}
		if _, err := p.WaitReady(ctx, o.URL); err != nil {
			t.Fatal(err)
		}
		if _, err := p.WaitCertificate(ctx, o.URL); core.AsProviderError(err) == nil || core.AsProviderError(err).Kind != core.ProviderRejected {
			t.Fatalf("%T: WaitCertificate before finalize = %v", p, err)
		}
		if _, err := p.Finalize(ctx, o.URL, csr); err != nil {
			t.Fatal(err)
		}
		if _, err := p.Finalize(ctx, o.URL, csr); err != nil {
			t.Fatalf("%T: repeat finalize: %v", p, err)
		}
		chain, err := p.WaitCertificate(ctx, o.URL)
		if err != nil {
			t.Fatal(err)
		}
		certs, _ := coretest.ParseChain(chain)
		id, _ := core.ARICertID(certs[0])
		if _, err := p.NewOrder(ctx, []string{"example.org"}, id); err != nil {
			t.Fatalf("%T: replaces: %v", p, err)
		}
		_, err = p.NewOrder(ctx, []string{"example.org"}, id)
		if pe := core.AsProviderError(err); pe == nil || pe.Kind != core.ProviderAlreadyReplaced {
			t.Fatalf("%T: second replaces = %v", p, err)
		}
		if _, err := p.RenewalInfo(ctx, id); err != nil {
			t.Fatalf("%T: renewal info: %v", p, err)
		}
		if _, err := p.GetOrder(ctx, o.URL+"0"); core.AsProviderError(err) == nil || core.AsProviderError(err).Kind != core.ProviderRejected {
			t.Fatalf("%T: unknown order = %v", p, err)
		}
	}
}

func finalizes(s *stubCA) int { return get(s, func() int { return s.finalizes }) }
func orders(s *stubCA) int    { return get(s, func() int { return len(s.orders) }) }
func newOrderReq(s *stubCA, i int) map[string]json.RawMessage {
	return get(s, func() map[string]json.RawMessage { return s.newOrders[i] })
}

func ecPEM(t *testing.T) []byte {
	t.Helper()
	der, err := x509.MarshalECPrivateKey(coretest.GenKey())
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der})
}

func rsaPEM(t *testing.T) []byte {
	t.Helper()
	return pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(coretest.GenRSAKey())})
}
