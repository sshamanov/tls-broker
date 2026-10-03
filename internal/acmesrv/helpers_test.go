package acmesrv

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sync"
	"testing"
	"time"

	jose "github.com/go-jose/go-jose/v4"

	"tls-broker/internal/core"
	"tls-broker/internal/core/coretest"
	"tls-broker/internal/httpx"
	"tls-broker/internal/names"
	"tls-broker/internal/store"
)

// ---- fake issuer ------------------------------------------------------------

// fakeIssuer implements core.Issuer on the real store with scripted
// behaviour: Admit persists a ready order (or returns admitErr), Finalize
// records the CSR and either completes at once (finalizeValid) or leaves the
// order processing until complete is called.
type fakeIssuer struct {
	st    *store.Store
	clock core.Clock
	cfg   core.ConfigSource
	ca    *testCA

	mu            sync.Mutex
	admitErr      error
	finalizeErr   error
	finalizeValid bool
	riRetryAfter  time.Duration
	admits        []core.AdmitRequest
	finalizes     []core.FinalizeRequest
}

var _ core.Issuer = (*fakeIssuer)(nil)

func (f *fakeIssuer) setAdmitErr(err error) { f.mu.Lock(); f.admitErr = err; f.mu.Unlock() }
func (f *fakeIssuer) setFinalizeValid(v bool) {
	f.mu.Lock()
	f.finalizeValid = v
	f.mu.Unlock()
}

func (f *fakeIssuer) Admits() []core.AdmitRequest {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]core.AdmitRequest(nil), f.admits...)
}

func (f *fakeIssuer) Finalizes() []core.FinalizeRequest {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]core.FinalizeRequest(nil), f.finalizes...)
}

func (f *fakeIssuer) Admit(ctx context.Context, req core.AdmitRequest) (*core.Order, error) {
	f.mu.Lock()
	f.admits = append(f.admits, req)
	err := f.admitErr
	f.mu.Unlock()
	if err != nil {
		return nil, err
	}
	now := f.clock.Now()
	if o, err := f.st.Orders().FindOpen(ctx, req.AccountID, req.Names.Key(), now); err == nil {
		return o, nil
	}
	o := &core.Order{
		ID: core.NewID(), Mode: core.ModeACME, AccountID: req.AccountID, Names: req.Names, Replaces: req.Replaces,
		SourceIP: req.SourceIP, GrantID: req.Decision.GrantID, Status: core.OrderReady, Prep: core.PrepIntent,
		Class: core.ClassACMEOrdinary, Provider: "primary", CreatedAt: now,
		ExpiresAt: now.Add(f.cfg.Current().Scheduler.OrderTTL),
	}
	if err := f.st.Orders().Create(ctx, o); err != nil {
		return nil, err
	}
	return f.st.Orders().Get(ctx, o.ID)
}

func (f *fakeIssuer) Finalize(ctx context.Context, req core.FinalizeRequest) (*core.Order, error) {
	f.mu.Lock()
	f.finalizes = append(f.finalizes, req)
	ferr, valid := f.finalizeErr, f.finalizeValid
	f.mu.Unlock()
	if ferr != nil {
		return nil, ferr
	}
	o, err := f.st.Orders().Get(ctx, req.OrderID)
	if err != nil {
		return nil, err
	}
	if o.AccountID != req.AccountID {
		return nil, core.ErrNotFound
	}
	csr, err := x509.ParseCertificateRequest(req.CSRDER)
	if err != nil {
		return nil, core.NewProblem(core.ProblemBadCSR, "unparsable")
	}
	set, err := names.NewSet(csr.DNSNames...)
	if err != nil || !set.Equal(o.Names) {
		return nil, core.NewProblem(core.ProblemBadCSR, "CSR names do not match the order")
	}
	_, first, err := f.st.Orders().BeginFinalize(ctx, o.ID, core.CSRHash(req.CSRDER), req.CSRDER, f.clock.Now())
	if err != nil {
		return nil, err
	}
	if first && valid {
		if err := f.complete(ctx, o.ID); err != nil {
			return nil, err
		}
	}
	return f.st.Orders().Get(ctx, o.ID)
}

// complete issues the certificate of a processing order.
func (f *fakeIssuer) complete(ctx context.Context, id string) error {
	o, err := f.st.Orders().Get(ctx, id)
	if err != nil {
		return err
	}
	chain, leaf := f.ca.issue(o.CSRDER, f.clock.Now())
	ari, err := core.ARICertID(leaf)
	if err != nil {
		return err
	}
	return f.st.Orders().Complete(ctx, id, &core.Certificate{
		ID: core.NewID(), OrderID: id, Mode: core.ModeACME, Names: o.Names, Provider: o.Provider,
		AccountURL: "https://primary.test/acme/acct/1", Serial: coretest.SerialHex(leaf), ARICertID: ari,
		NotBefore: leaf.NotBefore, NotAfter: leaf.NotAfter, IssuedAt: f.clock.Now(), ChainPEM: chain,
	}, f.clock.Now())
}

func (f *fakeIssuer) Issue(context.Context, core.IssueRequest) (*core.Certificate, error) {
	return nil, errors.New("not used")
}

func (f *fakeIssuer) RenewalInfo(ctx context.Context, ariCertID string) (core.RenewalInfo, error) {
	c, err := f.st.Certificates().GetByARICertID(ctx, ariCertID)
	if err != nil {
		return core.RenewalInfo{}, err
	}
	f.mu.Lock()
	ra := f.riRetryAfter
	f.mu.Unlock()
	return core.RenewalInfo{WindowStart: c.NotAfter.Add(-30 * 24 * time.Hour), WindowEnd: c.NotAfter.Add(-28 * 24 * time.Hour),
		ExplanationURL: "https://primary.test/ari-explained", RetryAfter: ra}, nil
}

func (f *fakeIssuer) Recover(context.Context) error { return nil }
func (f *fakeIssuer) Sweep(context.Context) error   { return nil }

// ---- test CA ----------------------------------------------------------------

type testCA struct {
	key  *ecdsa.PrivateKey
	cert *x509.Certificate
}

func newTestCA(t *testing.T) *testCA {
	key := coretest.GenKey()
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "acmesrv test intermediate"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(365 * 24 * time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign, SubjectKeyId: []byte{1, 2, 3, 4},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, _ := x509.ParseCertificate(der)
	return &testCA{key: key, cert: cert}
}

func (ca *testCA) issue(csrDER []byte, now time.Time) ([]byte, *x509.Certificate) {
	csr, err := x509.ParseCertificateRequest(csrDER)
	if err != nil {
		panic(err)
	}
	serial, _ := rand.Int(rand.Reader, big.NewInt(1<<62))
	tmpl := &x509.Certificate{
		SerialNumber: serial, Subject: pkix.Name{CommonName: csr.DNSNames[0]}, DNSNames: csr.DNSNames,
		NotBefore: now.Add(-time.Minute), NotAfter: now.Add(90 * 24 * time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, csr.PublicKey, ca.key)
	if err != nil {
		panic(err)
	}
	leaf, _ := x509.ParseCertificate(der)
	var buf bytes.Buffer
	_ = pem.Encode(&buf, &pem.Block{Type: "CERTIFICATE", Bytes: der})
	_ = pem.Encode(&buf, &pem.Block{Type: "CERTIFICATE", Bytes: ca.cert.Raw})
	return buf.Bytes(), leaf
}

// ---- environment ------------------------------------------------------------

type env struct {
	t      *testing.T
	ts     *httptest.Server
	st     *store.Store
	cfg    *coretest.FakeConfig
	gate   *coretest.FakeGate
	iss    *fakeIssuer
	aud    *coretest.FakeAuditor
	clock  *coretest.FakeClock
	server *Server
	base   string
}

func newEnv(t *testing.T, mod ...func(*Options)) *env {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	clock := coretest.NewFakeClock(time.Now().UTC().Truncate(time.Second))
	cfg := coretest.NewFakeConfig(nil)
	e := &env{t: t, st: st, cfg: cfg, gate: coretest.NewFakeGate(), aud: coretest.NewFakeAuditor(clock), clock: clock}
	e.iss = &fakeIssuer{st: st, clock: clock, cfg: cfg, ca: newTestCA(t), finalizeValid: true}
	o := Options{Config: cfg, Accounts: st.Accounts(), Orders: st.Orders(), Certificates: st.Certificates(),
		Gate: e.gate, Issuer: e.iss, Auditor: e.aud, Clock: clock}
	for _, m := range mod {
		m(&o)
	}
	e.server, err = New(o)
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	mux.Handle(PathPrefix+"/", e.server)
	e.ts = httptest.NewUnstartedServer(httpx.RealIP(httpx.NewResolver(httpx.Options{}))(mux))
	e.ts.StartTLS()
	t.Cleanup(e.ts.Close)
	cfg.Update(func(c *core.Config) { c.Server.ExternalURL = e.ts.URL })
	e.base = e.ts.URL + PathPrefix
	return e
}

func (e *env) url(p string) string { return e.base + p }

func (e *env) httpClient() *http.Client {
	return &http.Client{Transport: e.ts.Client().Transport, Timeout: 30 * time.Second}
}

// ---- raw JWS client ---------------------------------------------------------

// rawClient builds JWS requests by hand so tests can break any part.
type rawClient struct {
	e   *env
	key crypto.Signer
	kid string
}

func (e *env) newRaw(key crypto.Signer) *rawClient { return &rawClient{e: e, key: key} }

func algFor(key crypto.Signer) string {
	if _, ok := key.(*rsa.PrivateKey); ok {
		return "RS256"
	}
	switch key.(*ecdsa.PrivateKey).Curve.Params().BitSize {
	case 384:
		return "ES384"
	case 521:
		return "ES512"
	}
	return "ES256"
}

func jwkJSON(key crypto.Signer) json.RawMessage {
	b, err := (&jose.JSONWebKey{Key: key.Public()}).MarshalJSON()
	if err != nil {
		panic(err)
	}
	return b
}

// signJWS signs payload (nil means the empty POST-as-GET payload) with a
// protected header built from hdr.
func signJWS(key crypto.Signer, hdr map[string]any, payload []byte) []byte {
	hb, _ := json.Marshal(hdr)
	prot := base64.RawURLEncoding.EncodeToString(hb)
	pl := base64.RawURLEncoding.EncodeToString(payload)
	input := []byte(prot + "." + pl)
	digest := sha256.Sum256(input)
	var sig []byte
	switch k := key.(type) {
	case *ecdsa.PrivateKey:
		h := digest[:]
		switch k.Curve.Params().BitSize {
		case 384:
			d := sha512.Sum384(input)
			h = d[:]
		case 521:
			d := sha512.Sum512(input)
			h = d[:]
		}
		r, s, err := ecdsa.Sign(rand.Reader, k, h)
		if err != nil {
			panic(err)
		}
		size := (k.Curve.Params().BitSize + 7) / 8
		sig = make([]byte, 2*size)
		r.FillBytes(sig[:size])
		s.FillBytes(sig[size:])
	case *rsa.PrivateKey:
		var err error
		sig, err = rsa.SignPKCS1v15(rand.Reader, k, crypto.SHA256, digest[:])
		if err != nil {
			panic(err)
		}
	}
	body, _ := json.Marshal(map[string]string{"protected": prot, "payload": pl,
		"signature": base64.RawURLEncoding.EncodeToString(sig)})
	return body
}

func (c *rawClient) nonce() string {
	resp, err := c.e.httpClient().Head(c.e.url(pathNewNonce))
	if err != nil {
		c.e.t.Fatal(err)
	}
	resp.Body.Close()
	return resp.Header.Get("Replay-Nonce")
}

// header returns the default protected header for a request to url.
func (c *rawClient) header(url string) map[string]any {
	h := map[string]any{"alg": algFor(c.key), "nonce": c.nonce(), "url": url}
	if c.kid != "" {
		h["kid"] = c.kid
	} else {
		h["jwk"] = jwkJSON(c.key)
	}
	return h
}

type response struct {
	*http.Response
	body []byte
}

func (r *response) problem(t *testing.T) core.Problem {
	t.Helper()
	if ct := r.Header.Get("Content-Type"); ct != core.ProblemContentType {
		t.Fatalf("Content-Type %q, want problem (status %d, body %s)", ct, r.StatusCode, r.body)
	}
	var p core.Problem
	if err := json.Unmarshal(r.body, &p); err != nil {
		t.Fatalf("problem body %s: %v", r.body, err)
	}
	return p
}

func (c *rawClient) send(url string, body []byte, contentType string) *response {
	req, _ := http.NewRequest(http.MethodPost, url, bytes.NewReader(body))
	req.Header.Set("Content-Type", contentType)
	resp, err := c.e.httpClient().Do(req)
	if err != nil {
		c.e.t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return &response{Response: resp, body: b}
}

// post signs payload for url with the default header, modified by mods.
func (c *rawClient) post(url string, payload any, mods ...func(map[string]any)) *response {
	h := c.header(url)
	for _, m := range mods {
		m(h)
	}
	return c.send(url, signJWS(c.key, h, encodePayload(payload)), "application/jose+json")
}

func encodePayload(payload any) []byte {
	switch p := payload.(type) {
	case nil:
		return nil
	case []byte:
		return p
	case string:
		return []byte(p)
	}
	b, err := json.Marshal(payload)
	if err != nil {
		panic(err)
	}
	return b
}

// register creates an account for the client and sets its kid.
func (c *rawClient) register() *rawClient {
	c.e.t.Helper()
	r := c.post(c.e.url(pathNewAccount), map[string]any{"termsOfServiceAgreed": true})
	if r.StatusCode != http.StatusCreated {
		c.e.t.Fatalf("newAccount: %d %s", r.StatusCode, r.body)
	}
	c.kid = r.Header.Get("Location")
	return c
}

// newOrder creates an order and returns its decoded body and URL.
func (c *rawClient) newOrder(names ...string) (orderObj, string) {
	c.e.t.Helper()
	var ids []identifierObj
	for _, n := range names {
		ids = append(ids, identifierObj{Type: "dns", Value: n})
	}
	r := c.post(c.e.url(pathNewOrder), map[string]any{"identifiers": ids})
	if r.StatusCode != http.StatusCreated {
		c.e.t.Fatalf("newOrder: %d %s", r.StatusCode, r.body)
	}
	var o orderObj
	if err := json.Unmarshal(r.body, &o); err != nil {
		c.e.t.Fatal(err)
	}
	return o, r.Header.Get("Location")
}

func csrPayload(der []byte) map[string]string {
	return map[string]string{"csr": base64.RawURLEncoding.EncodeToString(der)}
}

func p384Key() *ecdsa.PrivateKey {
	k, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		panic(err)
	}
	return k
}
