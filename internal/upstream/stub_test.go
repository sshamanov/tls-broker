package upstream

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"

	"tls-broker/internal/core"
	"tls-broker/internal/core/coretest"
)

// stubCA is a small RFC 8555 server for tests: it verifies JWS signatures and
// nonces, keeps accounts, orders, authorizations and challenges, signs real
// certificates, serves renewal information and lets tests inject faults.
type stubCA struct {
	t   *testing.T
	srv *httptest.Server

	mu       sync.Mutex
	nonces   map[string]bool
	nonceSeq int
	// badNonce makes the next N signed POSTs fail with badNonce.
	badNonce int

	accounts    map[string]string           // JWK thumbprint -> account URL
	accountKeys map[string]*jose.JSONWebKey // account URL -> key
	newAccounts []map[string]json.RawMessage
	newAcctSent int // newAccount requests that reached the handler
	eabKeyID    string
	eabMAC      []byte
	eabVerified int

	orders       map[int]*stubOrder
	orderSeq     int
	newOrders    []map[string]json.RawMessage
	replaced     map[string]bool // ARI cert IDs with a live replacement order
	finalizes    int
	noARI        bool
	certs        map[string]*x509.Certificate // ARI cert ID -> leaf
	renewalRetry string                       // Retry-After on renewalInfo answers

	// readyAfter / validAfter: polls an order stays pending / processing.
	readyAfter, validAfter int
	pollRetry              string // Retry-After on order answers
	failValidation         bool
	noDNS01                bool

	faults   []*stubFault
	requests []string // "METHOD path" of every request

	rootKey, interKey *ecdsa.PrivateKey
	root, inter       *x509.Certificate
}

type stubOrder struct {
	id         int
	idents     []string
	status     string
	replaces   string
	authzs     []*stubAuthz
	pollsLeft  int
	cert       []byte
	errProblem map[string]any
}

type stubAuthz struct {
	ident    string
	wildcard bool
	token    string
	status   string
	chStatus string
	chError  map[string]any
}

// stubFault answers matching requests with a canned response.
type stubFault struct {
	match  func(r *http.Request) bool
	times  int // 0 = forever
	status int
	header map[string]string
	body   string
	delay  time.Duration
}

func newStubCA(t *testing.T) *stubCA {
	t.Helper()
	s := &stubCA{
		t: t, nonces: map[string]bool{}, accounts: map[string]string{}, accountKeys: map[string]*jose.JSONWebKey{},
		orders: map[int]*stubOrder{}, replaced: map[string]bool{}, certs: map[string]*x509.Certificate{},
		renewalRetry: "21600",
	}
	s.rootKey, s.interKey = coretest.GenKey(), coretest.GenKey()
	now := time.Now()
	rootTmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Stub Root"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.AddDate(10, 0, 0), IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign, SubjectKeyId: []byte{1, 2, 3, 4}}
	s.root = mustSign(t, rootTmpl, rootTmpl, &s.rootKey.PublicKey, s.rootKey)
	interTmpl := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "Stub Intermediate"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.AddDate(10, 0, 0), IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign, SubjectKeyId: []byte{5, 6, 7, 8}}
	s.inter = mustSign(t, interTmpl, s.root, &s.interKey.PublicKey, s.rootKey)
	s.srv = httptest.NewTLSServer(http.HandlerFunc(s.serve))
	t.Cleanup(s.srv.Close)
	return s
}

func mustSign(t *testing.T, tmpl, parent *x509.Certificate, pub crypto.PublicKey, key crypto.Signer) *x509.Certificate {
	t.Helper()
	der, err := x509.CreateCertificate(rand.Reader, tmpl, parent, pub, key)
	if err != nil {
		t.Fatal(err)
	}
	c, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func (s *stubCA) url(path string) string { return s.srv.URL + path }
func (s *stubCA) dirURL() string         { return s.url("/dir") }

func (s *stubCA) roots() *x509.CertPool {
	p := x509.NewCertPool()
	p.AddCert(s.srv.Certificate())
	return p
}

func (s *stubCA) inject(f *stubFault) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.faults = append(s.faults, f)
}

func (s *stubCA) count(prefix string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := 0
	for _, r := range s.requests {
		if strings.HasPrefix(r, prefix) {
			n++
		}
	}
	return n
}

func (s *stubCA) with(f func()) {
	s.mu.Lock()
	defer s.mu.Unlock()
	f()
}

// get reads stub state under the lock.
func get[T any](s *stubCA, f func() T) T {
	s.mu.Lock()
	defer s.mu.Unlock()
	return f()
}

func pathIs(method, prefix string) func(r *http.Request) bool {
	return func(r *http.Request) bool {
		return r.Method == method && strings.HasPrefix(r.URL.Path, prefix)
	}
}

func (s *stubCA) newNonce() string {
	s.nonceSeq++
	n := fmt.Sprintf("nonce-%d", s.nonceSeq)
	s.nonces[n] = true
	return n
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func problem(w http.ResponseWriter, status int, typ, detail string) {
	w.Header().Set("Content-Type", "application/problem+json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]any{"type": "urn:ietf:params:acme:error:" + typ, "detail": detail, "status": status})
}

func (s *stubCA) serve(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	s.requests = append(s.requests, r.Method+" "+r.URL.Path)
	var fault *stubFault
	for i, f := range s.faults {
		if f.match(r) {
			fault = f
			if f.times > 0 {
				f.times--
				if f.times == 0 {
					s.faults = append(s.faults[:i:i], s.faults[i+1:]...)
				}
			}
			break
		}
	}
	w.Header().Set("Replay-Nonce", s.newNonce())
	s.mu.Unlock()

	if fault != nil {
		if fault.delay > 0 {
			// Drain the body so the server notices a client that hangs up.
			_, _ = io.Copy(io.Discard, r.Body)
			select {
			case <-time.After(fault.delay):
			case <-r.Context().Done():
				return
			}
		}
		for k, v := range fault.header {
			w.Header().Set(k, v)
		}
		w.WriteHeader(fault.status)
		_, _ = io.WriteString(w, fault.body)
		return
	}

	switch {
	case r.URL.Path == "/dir":
		s.mu.Lock()
		noARI := s.noARI
		s.mu.Unlock()
		dir := map[string]any{"newNonce": s.url("/nonce"), "newAccount": s.url("/new-acct"), "newOrder": s.url("/new-order"),
			"keyChange": s.url("/key-change"), "revokeCert": s.url("/revoke")}
		if !noARI {
			dir["renewalInfo"] = s.url("/renewal-info")
		}
		writeJSON(w, http.StatusOK, dir)
	case r.URL.Path == "/nonce":
		w.WriteHeader(http.StatusOK)
	case strings.HasPrefix(r.URL.Path, "/renewal-info/"):
		s.renewalInfo(w, strings.TrimPrefix(r.URL.Path, "/renewal-info/"))
	case r.Method == http.MethodPost:
		s.post(w, r)
	default:
		http.NotFound(w, r)
	}
}

// post verifies the JWS and dispatches.
func (s *stubCA) post(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	jws, err := jose.ParseSigned(string(body), []jose.SignatureAlgorithm{jose.ES256, jose.ES384, jose.RS256})
	if err != nil || len(jws.Signatures) != 1 {
		problem(w, 400, "malformed", "bad JWS")
		return
	}
	hdr := jws.Signatures[0].Protected
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.nonces[hdr.Nonce] {
		problem(w, 400, "badNonce", "unknown nonce")
		return
	}
	delete(s.nonces, hdr.Nonce)
	if s.badNonce > 0 {
		s.badNonce--
		problem(w, 400, "badNonce", "injected bad nonce")
		return
	}
	if u, _ := hdr.ExtraHeaders["url"].(string); u != s.url(r.URL.Path) {
		problem(w, 401, "unauthorized", "url header mismatch")
		return
	}
	var key *jose.JSONWebKey
	acctURL := ""
	if r.URL.Path == "/new-acct" {
		key = hdr.JSONWebKey
	} else {
		acctURL = hdr.KeyID
		key = s.accountKeys[acctURL]
	}
	if key == nil {
		problem(w, 400, "accountDoesNotExist", "no such account")
		return
	}
	payload, err := jws.Verify(key)
	if err != nil {
		problem(w, 401, "unauthorized", "bad signature")
		return
	}

	parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
	switch {
	case r.URL.Path == "/new-acct":
		s.newAccount(w, key, payload)
	case r.URL.Path == "/new-order":
		s.newOrder(w, payload)
	case parts[0] == "order" && len(parts) == 2:
		s.getOrder(w, parts[1])
	case parts[0] == "order" && len(parts) == 3 && parts[2] == "finalize":
		s.finalize(w, parts[1], payload)
	case parts[0] == "authz" && len(parts) == 3:
		s.getAuthz(w, parts[1], parts[2])
	case parts[0] == "chall" && len(parts) == 3:
		s.challenge(w, parts[1], parts[2], payload)
	case parts[0] == "cert" && len(parts) == 2:
		s.getCert(w, parts[1])
	default:
		problem(w, 404, "malformed", "no such resource")
	}
}

func thumb(k *jose.JSONWebKey) string {
	b, _ := k.Thumbprint(crypto.SHA256)
	return base64.RawURLEncoding.EncodeToString(b)
}

func (s *stubCA) newAccount(w http.ResponseWriter, key *jose.JSONWebKey, payload []byte) {
	s.newAcctSent++
	var req map[string]json.RawMessage
	_ = json.Unmarshal(payload, &req)
	s.newAccounts = append(s.newAccounts, req)
	tp := thumb(key)
	if u, ok := s.accounts[tp]; ok {
		w.Header().Set("Location", u)
		writeJSON(w, http.StatusOK, map[string]any{"status": "valid"})
		return
	}
	if s.eabKeyID != "" {
		raw, ok := req["externalAccountBinding"]
		if !ok {
			problem(w, 403, "externalAccountRequired", "EAB required")
			return
		}
		eab, err := jose.ParseSigned(string(raw), []jose.SignatureAlgorithm{jose.HS256})
		if err != nil || len(eab.Signatures) != 1 {
			problem(w, 400, "malformed", "bad EAB")
			return
		}
		h := eab.Signatures[0].Protected
		if h.KeyID != s.eabKeyID || h.ExtraHeaders["url"] != s.url("/new-acct") {
			problem(w, 400, "malformed", "bad EAB header")
			return
		}
		inner, err := eab.Verify(s.eabMAC)
		if err != nil {
			problem(w, 400, "malformed", "bad EAB MAC")
			return
		}
		var innerKey jose.JSONWebKey
		if err := innerKey.UnmarshalJSON(inner); err != nil || thumb(&innerKey) != tp {
			problem(w, 400, "malformed", "EAB binds another key")
			return
		}
		s.eabVerified++
	}
	u := s.url(fmt.Sprintf("/acct/%d", len(s.accounts)+1))
	s.accounts[tp] = u
	s.accountKeys[u] = key
	w.Header().Set("Location", u)
	writeJSON(w, http.StatusCreated, map[string]any{"status": "valid"})
}

type stubIdent struct {
	Type  string `json:"type"`
	Value string `json:"value"`
}

func (s *stubCA) newOrder(w http.ResponseWriter, payload []byte) {
	var req map[string]json.RawMessage
	_ = json.Unmarshal(payload, &req)
	s.newOrders = append(s.newOrders, req)
	var idents []stubIdent
	_ = json.Unmarshal(req["identifiers"], &idents)
	var replaces string
	_ = json.Unmarshal(req["replaces"], &replaces)
	if len(idents) == 0 {
		problem(w, 400, "malformed", "no identifiers")
		return
	}
	if replaces != "" {
		if s.replaced[replaces] {
			problem(w, 409, "alreadyReplaced", "certificate already has a replacement order")
			return
		}
		s.replaced[replaces] = true
	}
	s.orderSeq++
	o := &stubOrder{id: s.orderSeq, status: "pending", replaces: replaces, pollsLeft: -1}
	for _, id := range idents {
		o.idents = append(o.idents, id.Value)
		base, wild := strings.CutPrefix(id.Value, "*.")
		o.authzs = append(o.authzs, &stubAuthz{ident: base, wildcard: wild, token: randTok(), status: "pending", chStatus: "pending"})
	}
	s.orders[o.id] = o
	w.Header().Set("Location", s.url(fmt.Sprintf("/order/%d", o.id)))
	writeJSON(w, http.StatusCreated, s.orderJSON(o))
}

func randTok() string {
	var b [12]byte
	_, _ = rand.Read(b[:])
	return base64.RawURLEncoding.EncodeToString(b[:])
}

func (s *stubCA) orderJSON(o *stubOrder) map[string]any {
	var ids []stubIdent
	var authzs []string
	for i, v := range o.idents {
		ids = append(ids, stubIdent{"dns", v})
		authzs = append(authzs, s.url(fmt.Sprintf("/authz/%d/%d", o.id, i)))
	}
	m := map[string]any{"status": o.status, "identifiers": ids, "authorizations": authzs,
		"finalize": s.url(fmt.Sprintf("/order/%d/finalize", o.id)), "expires": "2030-01-01T00:00:00Z"}
	if o.replaces != "" {
		m["replaces"] = o.replaces
	}
	if o.status == "valid" {
		m["certificate"] = s.url(fmt.Sprintf("/cert/%d", o.id))
	}
	if o.errProblem != nil {
		m["error"] = o.errProblem
	}
	return m
}

func (s *stubCA) order(id string) *stubOrder {
	n, _ := strconv.Atoi(id)
	return s.orders[n]
}

func (s *stubCA) getOrder(w http.ResponseWriter, id string) {
	o := s.order(id)
	if o == nil {
		problem(w, 404, "malformed", "no such order")
		return
	}
	if o.pollsLeft > 0 {
		o.pollsLeft--
	}
	if o.pollsLeft == 0 {
		switch o.status {
		case "pending":
			o.status = "ready"
		case "processing":
			o.status = "valid"
		}
		o.pollsLeft = -1
	}
	if s.pollRetry != "" && (o.status == "pending" || o.status == "processing") {
		w.Header().Set("Retry-After", s.pollRetry)
	}
	writeJSON(w, http.StatusOK, s.orderJSON(o))
}

func (s *stubCA) authzJSON(o *stubOrder, i int) map[string]any {
	a := o.authzs[i]
	ch := map[string]any{"type": "dns-01", "url": s.url(fmt.Sprintf("/chall/%d/%d", o.id, i)), "token": a.token, "status": a.chStatus}
	if a.chError != nil {
		ch["error"] = a.chError
	}
	chs := []map[string]any{{"type": "http-01", "url": s.url("/chall/x/http"), "token": a.token, "status": "pending"}}
	if !s.noDNS01 {
		chs = append(chs, ch)
	}
	m := map[string]any{"status": a.status, "identifier": stubIdent{"dns", a.ident}, "challenges": chs}
	if a.wildcard {
		m["wildcard"] = true
	}
	return m
}

func (s *stubCA) getAuthz(w http.ResponseWriter, oid, idx string) {
	o := s.order(oid)
	i, _ := strconv.Atoi(idx)
	if o == nil || i >= len(o.authzs) {
		problem(w, 404, "malformed", "no such authorization")
		return
	}
	writeJSON(w, http.StatusOK, s.authzJSON(o, i))
}

func (s *stubCA) challenge(w http.ResponseWriter, oid, idx string, payload []byte) {
	o := s.order(oid)
	i, _ := strconv.Atoi(idx)
	if o == nil || i >= len(o.authzs) {
		problem(w, 404, "malformed", "no such challenge")
		return
	}
	a := o.authzs[i]
	respond := func() {
		w.Header().Set("Link", fmt.Sprintf("<%s>;rel=\"up\"", s.url(fmt.Sprintf("/authz/%d/%d", o.id, i))))
		ch := s.authzJSON(o, i)["challenges"].([]map[string]any)
		writeJSON(w, http.StatusOK, ch[len(ch)-1])
	}
	if len(payload) == 0 { // POST-as-GET
		respond()
		return
	}
	if a.chStatus != "pending" {
		problem(w, 400, "malformed", "challenge is not pending")
		return
	}
	if s.failValidation {
		a.chStatus, a.status = "invalid", "invalid"
		a.chError = map[string]any{"type": "urn:ietf:params:acme:error:unauthorized", "detail": "incorrect TXT record", "status": 403}
		o.status = "invalid"
		respond()
		return
	}
	a.chStatus, a.status = "valid", "valid"
	all := true
	for _, az := range o.authzs {
		all = all && az.status == "valid"
	}
	if all && o.status == "pending" {
		if s.readyAfter > 0 {
			o.pollsLeft = s.readyAfter
		} else {
			o.status = "ready"
		}
	}
	respond()
}

// keyAuthValue is what the broker must publish for the challenge.
func (s *stubCA) keyAuthValue(orderID, idx int) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	o := s.orders[orderID]
	var key *jose.JSONWebKey
	for _, k := range s.accountKeys {
		key = k
	}
	sum := sha256.Sum256([]byte(o.authzs[idx].token + "." + thumb(key)))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

func (s *stubCA) finalize(w http.ResponseWriter, oid string, payload []byte) {
	o := s.order(oid)
	if o == nil {
		problem(w, 404, "malformed", "no such order")
		return
	}
	if o.status != "ready" {
		problem(w, 403, "orderNotReady", "order is "+o.status)
		return
	}
	var req struct {
		CSR string `json:"csr"`
	}
	_ = json.Unmarshal(payload, &req)
	der, err := base64.RawURLEncoding.DecodeString(req.CSR)
	if err != nil {
		problem(w, 400, "badCSR", "bad base64")
		return
	}
	csr, err := x509.ParseCertificateRequest(der)
	if err != nil {
		problem(w, 400, "badCSR", "cannot parse CSR")
		return
	}
	serial, _ := rand.Int(rand.Reader, big.NewInt(1<<62))
	now := time.Now()
	leaf := mustSign(s.t, &x509.Certificate{SerialNumber: serial.Add(serial, big.NewInt(1)), Subject: pkix.Name{CommonName: csr.DNSNames[0]},
		DNSNames: csr.DNSNames, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(90 * 24 * time.Hour),
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}, s.inter, csr.PublicKey, s.interKey)
	id, err := core.ARICertID(leaf)
	if err != nil {
		s.t.Error(err)
	}
	s.certs[id] = leaf
	var chain []byte
	for _, c := range []*x509.Certificate{leaf, s.inter, s.root} {
		chain = append(chain, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.Raw})...)
	}
	o.cert = chain
	s.finalizes++
	if s.validAfter > 0 {
		o.status, o.pollsLeft = "processing", s.validAfter
		w.Header().Set("Retry-After", "1")
	} else {
		o.status = "valid"
	}
	writeJSON(w, http.StatusOK, s.orderJSON(o))
}

func (s *stubCA) getCert(w http.ResponseWriter, oid string) {
	o := s.order(oid)
	if o == nil || o.cert == nil {
		problem(w, 404, "malformed", "no such certificate")
		return
	}
	w.Header().Set("Content-Type", "application/pem-certificate-chain")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(o.cert)
}

func (s *stubCA) renewalInfo(w http.ResponseWriter, id string) {
	s.mu.Lock()
	leaf, ok := s.certs[id]
	ra := s.renewalRetry
	s.mu.Unlock()
	if !ok {
		problem(w, 404, "malformed", "unknown certificate")
		return
	}
	start := leaf.NotBefore.Add(60 * 24 * time.Hour).UTC().Truncate(time.Second)
	if ra != "" {
		w.Header().Set("Retry-After", ra)
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"suggestedWindow": map[string]string{"start": start.Format(time.RFC3339), "end": start.Add(48 * time.Hour).Format(time.RFC3339)},
		"explanationURL":  "https://ca.test/why",
	})
}

// stepClock is a core.Clock that never waits: After records the duration,
// moves the clock forward by it and fires at once.
type stepClock struct {
	mu    sync.Mutex
	now   time.Time
	waits []time.Duration
}

func newStepClock() *stepClock {
	return &stepClock{now: time.Date(2026, 10, 2, 12, 0, 0, 0, time.UTC)}
}

func (c *stepClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *stepClock) After(d time.Duration) <-chan time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.waits = append(c.waits, d)
	if d > 0 {
		c.now = c.now.Add(d)
	}
	ch := make(chan time.Time, 1)
	ch <- c.now
	return ch
}

func (c *stepClock) Waits() []time.Duration {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]time.Duration(nil), c.waits...)
}

var _ core.Clock = (*stepClock)(nil)

// ctxT returns a context bounded in real time for one test.
func ctxT(t *testing.T) context.Context {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	t.Cleanup(cancel)
	return ctx
}
