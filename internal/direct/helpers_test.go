package direct

import (
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"net/netip"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"tls-broker/internal/core"
	"tls-broker/internal/core/coretest"
	"tls-broker/internal/metrics"
	"tls-broker/internal/names"
	"tls-broker/internal/store"
)

const day = 24 * time.Hour

var (
	ctx    = context.Background()
	device = netip.MustParseAddr("192.0.2.10")
)

// ---- keys -----------------------------------------------------------------

var (
	keyPoolOnce sync.Once
	keyPool     []*rsa.PrivateKey
	keyNext     atomic.Int64
)

// poolKey hands out pre-generated RSA-2048 keys round robin, so consecutive
// calls never return the same key and tests do not pay for key generation.
func poolKey(bits int) (*rsa.PrivateKey, error) {
	if bits != 2048 {
		return nil, errors.New("unexpected key size")
	}
	keyPoolOnce.Do(func() {
		for range 3 {
			k, err := rsa.GenerateKey(rand.Reader, 2048)
			if err != nil {
				panic(err)
			}
			keyPool = append(keyPool, k)
		}
	})
	return keyPool[int(keyNext.Add(1))%len(keyPool)], nil
}

// ---- test CA --------------------------------------------------------------

type testCA struct {
	rootKey, intKey *ecdsa.PrivateKey
	root, inter     *x509.Certificate
	serial          atomic.Int64
}

func newTestCA() *testCA {
	ca := &testCA{rootKey: coretest.GenKey(), intKey: coretest.GenKey()}
	ca.serial.Store(1000)
	t0 := time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)
	mk := func(tmpl, parent *x509.Certificate, pub any, key *ecdsa.PrivateKey) *x509.Certificate {
		der, err := x509.CreateCertificate(rand.Reader, tmpl, parent, pub, key)
		if err != nil {
			panic(err)
		}
		c, _ := x509.ParseCertificate(der)
		return c
	}
	rt := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Test Root"},
		NotBefore: t0, NotAfter: t0.AddDate(20, 0, 0), IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign}
	ca.root = mk(rt, rt, &ca.rootKey.PublicKey, ca.rootKey)
	it := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "Test Intermediate"},
		NotBefore: t0, NotAfter: t0.AddDate(20, 0, 0), IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign}
	ca.inter = mk(it, ca.root, &ca.intKey.PublicKey, ca.rootKey)
	return ca
}

func pemCert(c *x509.Certificate) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.Raw})
}

// sign issues a leaf for pub naming dnsNames; the chain is leaf +
// intermediate (+ root when withRoot).
func (ca *testCA) sign(pub any, dnsNames []string, nb, na time.Time, withRoot bool) (*x509.Certificate, []byte) {
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(ca.serial.Add(1)), Subject: pkix.Name{CommonName: dnsNames[0]},
		DNSNames: dnsNames, NotBefore: nb, NotAfter: na, KeyUsage: x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.inter, pub, ca.intKey)
	if err != nil {
		panic(err)
	}
	leaf, _ := x509.ParseCertificate(der)
	chain := append(pemCert(leaf), pemCert(ca.inter)...)
	if withRoot {
		chain = append(chain, pemCert(ca.root)...)
	}
	return leaf, chain
}

// ---- fake issuer ----------------------------------------------------------

// fakeIssuer is a core.Issuer whose Issue signs the CSR with a test CA after
// optional scripted blocking and failures. Only Issue and RenewalInfo are
// used by the direct cache.
type fakeIssuer struct {
	ca     *testCA
	clock  *coretest.FakeClock
	orders core.OrderStore // optional

	mu       sync.Mutex
	lifetime time.Duration
	calls    []core.IssueRequest
	errs     []error // consumed one per call; nil entries succeed
	failAll  error   // used when errs is empty
	block    chan struct{}
	started  chan struct{}
	withRoot bool
	ari      map[string]core.RenewalInfo
	ariCalls int
}

func newFakeIssuer(clock *coretest.FakeClock) *fakeIssuer {
	return &fakeIssuer{ca: newTestCA(), clock: clock, lifetime: 90 * day,
		started: make(chan struct{}, 100), ari: map[string]core.RenewalInfo{}}
}

func (f *fakeIssuer) Admit(context.Context, core.AdmitRequest) (*core.Order, error) {
	return nil, errors.New("not used")
}
func (f *fakeIssuer) Finalize(context.Context, core.FinalizeRequest) (*core.Order, error) {
	return nil, errors.New("not used")
}
func (f *fakeIssuer) Recover(context.Context) error { return nil }
func (f *fakeIssuer) Sweep(context.Context) error   { return nil }

func (f *fakeIssuer) Issue(ctx context.Context, req core.IssueRequest) (*core.Certificate, error) {
	f.mu.Lock()
	f.calls = append(f.calls, req)
	var err error
	if len(f.errs) > 0 {
		err, f.errs = f.errs[0], f.errs[1:]
	} else {
		err = f.failAll
	}
	block, lifetime, withRoot := f.block, f.lifetime, f.withRoot
	f.mu.Unlock()
	f.started <- struct{}{}
	if block != nil {
		select {
		case <-block:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	if err != nil {
		return nil, err
	}
	csr, perr := x509.ParseCertificateRequest(req.CSRDER)
	if perr != nil || csr.CheckSignature() != nil {
		return nil, core.NewProblem(core.ProblemBadCSR, "bad CSR")
	}
	if len(csr.DNSNames) != 1 || csr.DNSNames[0] != req.Identifier {
		return nil, core.NewProblem(core.ProblemBadCSR, "CSR names %v", csr.DNSNames)
	}
	now := f.clock.Now()
	leaf, chain := f.ca.sign(csr.PublicKey, csr.DNSNames, now, now.Add(lifetime), withRoot)
	ari, _ := core.ARICertID(leaf)
	cert := &core.Certificate{ID: core.NewID(), Mode: core.ModeDirect, Names: names.MustSet(req.Identifier),
		Provider: "primary", Serial: leaf.SerialNumber.Text(16), ARICertID: ari,
		NotBefore: leaf.NotBefore, NotAfter: leaf.NotAfter, IssuedAt: now, ChainPEM: chain}
	if f.orders != nil { // persist like the engine does, so repair can find it
		o := &core.Order{ID: core.NewID(), Mode: core.ModeDirect, Names: cert.Names, SourceIP: req.SourceIP,
			Status: core.OrderReady, Prep: core.PrepIntent, Class: core.ClassDirectMiss, Provider: "primary",
			CreatedAt: now, ExpiresAt: now.Add(15 * time.Minute), UpdatedAt: now}
		if err := f.orders.Create(ctx, o); err != nil {
			return nil, err
		}
		if _, _, err := f.orders.BeginFinalize(ctx, o.ID, core.CSRHash(req.CSRDER), req.CSRDER, now); err != nil {
			return nil, err
		}
		cert.OrderID = o.ID
		if err := f.orders.Complete(ctx, o.ID, cert, now); err != nil {
			return nil, err
		}
		cert.ChainPEM = chain
	}
	return cert, nil
}

func (f *fakeIssuer) RenewalInfo(_ context.Context, ariCertID string) (core.RenewalInfo, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.ariCalls++
	if ri, ok := f.ari[ariCertID]; ok {
		return ri, nil
	}
	if ri, ok := f.ari["*"]; ok {
		return ri, nil
	}
	return core.RenewalInfo{}, core.ErrNotFound
}

func (f *fakeIssuer) Calls() []core.IssueRequest {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]core.IssueRequest(nil), f.calls...)
}

func (f *fakeIssuer) ARICalls() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.ariCalls
}

func (f *fakeIssuer) set(fn func(f *fakeIssuer)) {
	f.mu.Lock()
	defer f.mu.Unlock()
	fn(f)
}

var _ core.Issuer = (*fakeIssuer)(nil)

// ---- metrics --------------------------------------------------------------

type fakeRecorder struct {
	metrics.Nop
	hits, misses, renewOK, renewFailed atomic.Int64
	mu                                 sync.Mutex
	expiry                             map[string]time.Time
}

func (r *fakeRecorder) DirectCacheHit()  { r.hits.Add(1) }
func (r *fakeRecorder) DirectCacheMiss() { r.misses.Add(1) }
func (r *fakeRecorder) DirectRenewal(res metrics.IssueResult) {
	if res == metrics.IssueOK {
		r.renewOK.Add(1)
	} else {
		r.renewFailed.Add(1)
	}
}
func (r *fakeRecorder) CertExpiry(id string, na time.Time) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.expiry == nil {
		r.expiry = map[string]time.Time{}
	}
	r.expiry[id] = na
}

// ---- environment ----------------------------------------------------------

type env struct {
	t       *testing.T
	clock   *coretest.FakeClock
	cfg     *coretest.FakeConfig
	db      *store.Store
	iss     *fakeIssuer
	gate    *coretest.FakeGate
	aud     *coretest.FakeAuditor
	rec     *fakeRecorder
	svc     *Service
	dataDir string
}

func newEnv(t *testing.T, mutate ...func(c *core.Config)) *env {
	t.Helper()
	e := &env{t: t, clock: coretest.NewFakeClock(), dataDir: t.TempDir()}
	c := coretest.NewConfig()
	c.DataDir = e.dataDir
	for _, m := range mutate {
		m(c)
	}
	e.cfg = coretest.NewFakeConfig(c)
	db, err := store.Open(filepath.Join(t.TempDir(), "broker.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	e.db = db
	e.iss = newFakeIssuer(e.clock)
	e.iss.orders = db.Orders()
	e.gate = coretest.NewFakeGate()
	e.aud = coretest.NewFakeAuditor(e.clock)
	e.rec = &fakeRecorder{}
	e.svc = e.newService()
	return e
}

// newService builds a service on the environment's store and data (as after
// a restart).
func (e *env) newService() *Service {
	s, err := New(Options{Config: e.cfg, Issuer: e.iss, Gate: e.gate, Entries: e.db.Direct(),
		Lineages: e.db.Lineages(), Certificates: e.db.Certificates(), Auditor: e.aud, Metrics: e.rec,
		Clock: e.clock, NewKey: poolKey})
	if err != nil {
		e.t.Fatal(err)
	}
	e.t.Cleanup(s.Close)
	return s
}

// idle waits until every background job has finished.
func (e *env) idle() { e.svc.wg.Wait() }

func (e *env) get(id string) (*Cert, *core.Problem) {
	e.t.Helper()
	c, err := e.svc.Get(ctx, device, id)
	e.idle()
	if err != nil {
		p := core.AsProblem(err)
		if p == nil {
			e.t.Fatalf("Get(%s): non-problem error %v", id, err)
		}
		return nil, p
	}
	return c, nil
}

func (e *env) mustGet(id string) *Cert {
	e.t.Helper()
	c, p := e.get(id)
	if p != nil {
		e.t.Fatalf("Get(%s): %v (status %d)", id, p, p.Status)
	}
	return c
}

func (e *env) entry(id string) *core.DirectEntry {
	e.t.Helper()
	en, err := e.db.Direct().Get(ctx, id)
	if err != nil {
		e.t.Fatal(err)
	}
	return en
}

func (e *env) wantCalls(n int) {
	e.t.Helper()
	if got := len(e.iss.Calls()); got != n {
		e.t.Fatalf("issuer calls = %d, want %d", got, n)
	}
}
