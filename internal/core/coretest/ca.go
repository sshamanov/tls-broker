package coretest

import (
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha1"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"math/big"
	"slices"
	"strings"
	"sync"
	"time"

	"tls-broker/internal/core"
	"tls-broker/internal/names"
)

// Op names a FakeCA operation for fault injection and call counting.
type Op string

const (
	OpAny             Op = "*"
	OpAccountURL      Op = "AccountURL"
	OpNewOrder        Op = "NewOrder"
	OpGetOrder        Op = "GetOrder"
	OpDNSChallenges   Op = "DNSChallenges"
	OpAccept          Op = "Accept"
	OpWaitReady       Op = "WaitReady"
	OpFinalize        Op = "Finalize"
	OpWaitCertificate Op = "WaitCertificate"
	OpRenewalInfo     Op = "RenewalInfo"
)

// Fault is an injected misbehaviour of the FakeCA.
type Fault struct {
	// Op selects the operation; OpAny matches all.
	Op Op
	// Err is returned by the operation. Build it with the CA's RateLimited,
	// Busy, Down and Rejected helpers. Nil with a Delay gives a slow but
	// successful call.
	Err error
	// Delay makes the operation wait that long on the CA's clock (or until
	// ctx ends) before doing anything else.
	Delay time.Duration
	// Times is how many calls the fault affects; 0 means until
	// ClearFaults.
	Times int
	// AfterEffect makes the operation take effect at the CA and then
	// return Err: with OpNewOrder the order exists (and is counted) but
	// the caller never learns its URL; with OpFinalize the certificate is
	// issued but the caller gets an error.
	AfterEffect bool
}

// CAStats are the FakeCA's counters.
type CAStats struct {
	// AccountsRegistered is 0 or 1.
	AccountsRegistered int
	// OrdersCreated counts orders that came to exist at the CA, including
	// those hidden from the caller by an AfterEffect fault.
	OrdersCreated int
	// ExemptOrders counts orders created with `replaces` inside the
	// predecessor's suggested window while the CA exempts ARI renewals.
	ExemptOrders int
	// Finalizations counts CSR submissions accepted by the CA (not
	// idempotent repeats).
	Finalizations int
	// CertificatesIssued counts certificates signed.
	CertificatesIssued int
	// Calls counts every call per operation, including failed ones.
	Calls map[Op]int
}

// CAOrder is a read-only view of an order at the FakeCA.
type CAOrder struct {
	URL      string
	Names    []string
	Status   core.UpstreamStatus
	Replaces string
	// Exempt reports that the order was created as a rate-limit-exempt
	// ARI renewal.
	Exempt  bool
	Expires time.Time
	// CertID is the ARI certificate identifier of the issued certificate.
	CertID string
}

// FakeCA is a core.Provider backed by a small real CA: it has its own root
// and intermediate, tracks orders and authorizations, validates dns-01 by
// asking a TXT lookup function, signs CSRs into real X.509 certificates and
// serves renewal information. It follows Boulder's `replaces` rules.
//
// Unlike a real CA everything is synchronous: Accept validates at once and
// Finalize issues at once, so WaitReady and WaitCertificate never wait unless
// a Fault delays them.
type FakeCA struct {
	name  string
	clock core.Clock

	mu         sync.Mutex
	caps       core.ProviderCaps
	lookup     func(ctx context.Context, name string) ([]string, error)
	lifetime   time.Duration
	orderTTL   time.Duration
	registered bool
	orders     map[string]*caOrder
	orderList  []*caOrder
	certs      map[string]*caCert // by ARI certificate identifier
	faults     []*Fault
	stats      CAStats
	seq        int

	rootKey, interKey *ecdsa.PrivateKey
	root, inter       *x509.Certificate
}

type caOrder struct {
	url      string
	names    []string // sorted, normalized
	status   core.UpstreamStatus
	expires  time.Time
	replaces string
	exempt   bool
	authzs   []*caAuthz
	csrHash  string
	chain    []byte
	certID   string
	problem  *core.Problem
}

type caAuthz struct {
	url, chURL string
	identifier string
	wildcard   bool
	value      string
	status     string // pending | valid | invalid
}

type caCert struct {
	id          string
	cert        *x509.Certificate
	names       []string
	replacedBy  *caOrder
	windowStart time.Time
	windowEnd   time.Time
}

var _ core.Provider = (*FakeCA)(nil)

// NewFakeCA creates a CA named name using clock for all time decisions.
//
// Defaults: ARI supported and exempt, CAA issuer "<name>.test", accounturi
// honoured, 90-day certificates, 7-day orders, and no TXT lookup — which
// means every challenge validates. Call SetTXTLookup (for example with
// FakeResolver.LookupTXT) to make validation depend on published values.
func NewFakeCA(name string, clock core.Clock) *FakeCA {
	ca := &FakeCA{
		name:     name,
		clock:    clock,
		caps:     core.ProviderCaps{ARI: true, ARIExempt: true, CAAIssuers: []string{name + ".test"}, AccountURIHonoured: true},
		lifetime: 90 * 24 * time.Hour,
		orderTTL: 7 * 24 * time.Hour,
		orders:   map[string]*caOrder{},
		certs:    map[string]*caCert{},
		stats:    CAStats{Calls: map[Op]int{}},
	}
	now := clock.Now()
	ca.rootKey, ca.interKey = GenKey(), GenKey()
	rootTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Fake Root " + name},
		NotBefore: now.Add(-24 * time.Hour), NotAfter: now.AddDate(30, 0, 0),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		SubjectKeyId: keyID(ca.rootKey),
	}
	ca.root = mustCert(rootTmpl, rootTmpl, &ca.rootKey.PublicKey, ca.rootKey)
	interTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "Fake Intermediate " + name},
		NotBefore: now.Add(-24 * time.Hour), NotAfter: now.AddDate(30, 0, 0),
		IsCA: true, BasicConstraintsValid: true, MaxPathLenZero: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		SubjectKeyId: keyID(ca.interKey),
	}
	ca.inter = mustCert(interTmpl, ca.root, &ca.interKey.PublicKey, ca.rootKey)
	return ca
}

func keyID(k *ecdsa.PrivateKey) []byte {
	der, err := x509.MarshalPKIXPublicKey(&k.PublicKey)
	if err != nil {
		panic(err)
	}
	sum := sha1.Sum(der)
	return sum[:]
}

func mustCert(tmpl, parent *x509.Certificate, pub *ecdsa.PublicKey, signer *ecdsa.PrivateKey) *x509.Certificate {
	der, err := x509.CreateCertificate(rand.Reader, tmpl, parent, pub, signer)
	if err != nil {
		panic(err)
	}
	c, err := x509.ParseCertificate(der)
	if err != nil {
		panic(err)
	}
	return c
}

// ---- configuration --------------------------------------------------------

// SetCaps replaces the capabilities reported by Caps and applied by the CA.
func (ca *FakeCA) SetCaps(c core.ProviderCaps) {
	ca.mu.Lock()
	defer ca.mu.Unlock()
	ca.caps = c
}

// SetTXTLookup sets the function the CA uses to validate dns-01: Accept
// succeeds only if the lookup of the challenge's record name returns the
// expected value. nil makes every challenge validate.
func (ca *FakeCA) SetTXTLookup(f func(ctx context.Context, name string) ([]string, error)) {
	ca.mu.Lock()
	defer ca.mu.Unlock()
	ca.lookup = f
}

// SetCertLifetime sets the validity of certificates issued from now on.
func (ca *FakeCA) SetCertLifetime(d time.Duration) {
	ca.mu.Lock()
	defer ca.mu.Unlock()
	ca.lifetime = d
}

// SetRenewalWindow overrides the suggested renewal window of a certificate.
// It reports false when the CA did not issue such a certificate.
func (ca *FakeCA) SetRenewalWindow(ariCertID string, start, end time.Time) bool {
	ca.mu.Lock()
	defer ca.mu.Unlock()
	c, ok := ca.certs[ariCertID]
	if ok {
		c.windowStart, c.windowEnd = start, end
	}
	return ok
}

// Inject adds a fault. Faults are consulted in the order they were injected;
// the first one matching the operation applies.
func (ca *FakeCA) Inject(f Fault) {
	ca.mu.Lock()
	defer ca.mu.Unlock()
	ca.faults = append(ca.faults, &f)
}

// ClearFaults removes all faults.
func (ca *FakeCA) ClearFaults() {
	ca.mu.Lock()
	defer ca.mu.Unlock()
	ca.faults = nil
}

// RateLimited builds the error of a CA rate limit (ACME rateLimited).
func (ca *FakeCA) RateLimited(retryAfter time.Duration) error {
	return &core.ProviderError{Provider: ca.name, Kind: core.ProviderRateLimited, RetryAfter: retryAfter,
		Problem: core.NewProblem(core.ProblemRateLimited, "too many requests")}
}

// Busy builds the error of a CA asking to back off (503 with Retry-After).
func (ca *FakeCA) Busy(retryAfter time.Duration) error {
	return &core.ProviderError{Provider: ca.name, Kind: core.ProviderBusy, RetryAfter: retryAfter,
		Problem: core.NewProblem(core.ProblemServerInternal, "service busy").WithStatus(503)}
}

// Down builds the error of an unreachable CA.
func (ca *FakeCA) Down() error {
	return &core.ProviderError{Provider: ca.name, Kind: core.ProviderDown, Err: fmt.Errorf("fake CA %s is down", ca.name)}
}

// Rejected builds a ProviderRejected error with the given ACME problem type.
func (ca *FakeCA) Rejected(problemType, detail string) error {
	return &core.ProviderError{Provider: ca.name, Kind: core.ProviderRejected, Problem: core.NewProblem(problemType, "%s", detail)}
}

// ---- inspection -----------------------------------------------------------

// Stats returns a copy of the counters.
func (ca *FakeCA) Stats() CAStats {
	ca.mu.Lock()
	defer ca.mu.Unlock()
	s := ca.stats
	s.Calls = make(map[Op]int, len(ca.stats.Calls))
	for k, v := range ca.stats.Calls {
		s.Calls[k] = v
	}
	return s
}

// Orders returns every order at the CA in creation order.
func (ca *FakeCA) Orders() []CAOrder {
	ca.mu.Lock()
	defer ca.mu.Unlock()
	now := ca.clock.Now()
	out := make([]CAOrder, 0, len(ca.orderList))
	for _, o := range ca.orderList {
		out = append(out, CAOrder{URL: o.url, Names: slices.Clone(o.names), Status: o.statusAt(now),
			Replaces: o.replaces, Exempt: o.exempt, Expires: o.expires, CertID: o.certID})
	}
	return out
}

// ExpireOrder makes an order expire now, as if nobody finished it in time.
// It reports false for an unknown URL.
func (ca *FakeCA) ExpireOrder(orderURL string) bool {
	ca.mu.Lock()
	defer ca.mu.Unlock()
	o, ok := ca.orders[orderURL]
	if ok {
		o.expires = ca.clock.Now()
	}
	return ok
}

// RootPEM returns the root certificate (which is never part of a chain).
func (ca *FakeCA) RootPEM() []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ca.root.Raw})
}

// VerifyChain checks that chainPEM is a leaf plus intermediates issued by
// this CA, valid at the CA clock's current time for dnsName (pass "" to skip
// the name check), and that the root is not included. It returns the leaf.
func (ca *FakeCA) VerifyChain(chainPEM []byte, dnsName string) (*x509.Certificate, error) {
	certs, err := ParseChain(chainPEM)
	if err != nil {
		return nil, err
	}
	roots, inters := x509.NewCertPool(), x509.NewCertPool()
	roots.AddCert(ca.root)
	for _, c := range certs[1:] {
		if c.Equal(ca.root) {
			return nil, fmt.Errorf("chain includes the root certificate")
		}
		inters.AddCert(c)
	}
	_, err = certs[0].Verify(x509.VerifyOptions{Roots: roots, Intermediates: inters, DNSName: dnsName,
		CurrentTime: ca.clock.Now(), KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}})
	if err != nil {
		return nil, err
	}
	return certs[0], nil
}

// ---- core.Provider --------------------------------------------------------

// Name implements core.Provider.
func (ca *FakeCA) Name() string { return ca.name }

// Caps implements core.Provider.
func (ca *FakeCA) Caps() core.ProviderCaps {
	ca.mu.Lock()
	defer ca.mu.Unlock()
	c := ca.caps
	c.CAAIssuers = slices.Clone(c.CAAIssuers)
	return c
}

// accountURL is the fixed account URL of this CA.
func (ca *FakeCA) accountURL() string { return "https://" + ca.name + ".test/acme/acct/1" }

// begin counts the call, applies delay and plain error faults, and returns
// the after-effect error (to be returned once the operation has happened).
func (ca *FakeCA) begin(ctx context.Context, op Op) (after error, err error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	ca.mu.Lock()
	ca.stats.Calls[op]++
	var f *Fault
	for i, c := range ca.faults {
		if c.Op == op || c.Op == OpAny {
			f = &Fault{}
			*f = *c
			if c.Times > 0 {
				c.Times--
				if c.Times == 0 {
					ca.faults = slices.Delete(ca.faults, i, i+1)
				}
			}
			break
		}
	}
	ca.mu.Unlock()
	if f == nil {
		return nil, nil
	}
	if f.Delay > 0 {
		if err := core.Sleep(ctx, ca.clock, f.Delay); err != nil {
			return nil, err
		}
	}
	if f.Err != nil && f.AfterEffect {
		return f.Err, nil
	}
	return nil, f.Err
}

// AccountURL implements core.Provider.
func (ca *FakeCA) AccountURL(ctx context.Context) (string, error) {
	if _, err := ca.begin(ctx, OpAccountURL); err != nil {
		return "", err
	}
	ca.mu.Lock()
	defer ca.mu.Unlock()
	if !ca.registered {
		ca.registered = true
		ca.stats.AccountsRegistered++
	}
	return ca.accountURL(), nil
}

func (o *caOrder) statusAt(now time.Time) core.UpstreamStatus {
	if (o.status == core.UpstreamPending || o.status == core.UpstreamReady) && !now.Before(o.expires) {
		return core.UpstreamInvalid
	}
	return o.status
}

func (o *caOrder) view(now time.Time) core.UpstreamOrder {
	u := core.UpstreamOrder{URL: o.url, Status: o.statusAt(now), Expires: o.expires, Names: slices.Clone(o.names),
		Replaces: o.replaces, FinalizeURL: o.url + "/finalize"}
	for _, a := range o.authzs {
		u.AuthorizationURLs = append(u.AuthorizationURLs, a.url)
	}
	switch u.Status {
	case core.UpstreamValid:
		u.CertificateURL = o.url + "/cert"
	case core.UpstreamInvalid:
		u.Error = o.problem
		if u.Error == nil {
			u.Error = core.NewProblem(core.ProblemMalformed, "order expired")
		}
	}
	return u
}

func (ca *FakeCA) rejected(typ, format string, args ...any) error {
	return &core.ProviderError{Provider: ca.name, Kind: core.ProviderRejected, Problem: core.NewProblem(typ, format, args...)}
}

func randToken() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic(err)
	}
	return base64.RawURLEncoding.EncodeToString(b[:])
}

// NewOrder implements core.Provider.
func (ca *FakeCA) NewOrder(ctx context.Context, orderNames []string, replaces string) (core.UpstreamOrder, error) {
	after, err := ca.begin(ctx, OpNewOrder)
	if err != nil {
		return core.UpstreamOrder{}, err
	}
	set, err := names.NewSet(orderNames...)
	if err != nil {
		return core.UpstreamOrder{}, ca.rejected(core.ProblemRejectedIdentifier, "%v", err)
	}
	ca.mu.Lock()
	defer ca.mu.Unlock()
	now := ca.clock.Now()

	var pred *caCert
	exempt := false
	if replaces != "" {
		if !ca.caps.ARI {
			return core.UpstreamOrder{}, ca.rejected(core.ProblemMalformed, "this CA does not support replaces")
		}
		pred = ca.certs[replaces]
		if pred == nil {
			return core.UpstreamOrder{}, ca.rejected(core.ProblemMalformed, "replaces: certificate %q was not issued by this account", replaces)
		}
		shared := false
		for _, n := range pred.names {
			if set.Contains(n) {
				shared = true
			}
		}
		if !shared {
			return core.UpstreamOrder{}, ca.rejected(core.ProblemMalformed, "replaces: order shares no identifier with the certificate")
		}
		if r := pred.replacedBy; r != nil && r.statusAt(now) != core.UpstreamInvalid {
			return core.UpstreamOrder{}, &core.ProviderError{Provider: ca.name, Kind: core.ProviderAlreadyReplaced,
				Problem: core.NewProblem(core.ProblemAlreadyReplaced, "certificate already has a replacement order")}
		}
		start, end := ca.windowOf(pred)
		exempt = ca.caps.ARIExempt && !now.Before(start) && now.Before(end)
	}

	ca.seq++
	o := &caOrder{
		url:      fmt.Sprintf("https://%s.test/acme/order/%d", ca.name, ca.seq),
		names:    set.Names(),
		status:   core.UpstreamPending,
		expires:  now.Add(ca.orderTTL),
		replaces: replaces,
		exempt:   exempt,
	}
	for i, n := range o.names {
		o.authzs = append(o.authzs, &caAuthz{
			url:        fmt.Sprintf("%s/authz/%d", o.url, i+1),
			chURL:      fmt.Sprintf("%s/chall/%d", o.url, i+1),
			identifier: names.Base(n),
			wildcard:   names.IsWildcard(n),
			value:      randToken(),
			status:     "pending",
		})
	}
	ca.orders[o.url] = o
	ca.orderList = append(ca.orderList, o)
	ca.stats.OrdersCreated++
	if exempt {
		ca.stats.ExemptOrders++
	}
	if pred != nil {
		pred.replacedBy = o
	}
	if after != nil {
		return core.UpstreamOrder{}, after
	}
	return o.view(now), nil
}

// GetOrder implements core.Provider.
func (ca *FakeCA) GetOrder(ctx context.Context, orderURL string) (core.UpstreamOrder, error) {
	if _, err := ca.begin(ctx, OpGetOrder); err != nil {
		return core.UpstreamOrder{}, err
	}
	ca.mu.Lock()
	defer ca.mu.Unlock()
	o, ok := ca.orders[orderURL]
	if !ok {
		return core.UpstreamOrder{}, ca.rejected(core.ProblemMalformed, "no such order")
	}
	return o.view(ca.clock.Now()), nil
}

// DNSChallenges implements core.Provider.
func (ca *FakeCA) DNSChallenges(ctx context.Context, order core.UpstreamOrder) ([]core.UpstreamChallenge, error) {
	if _, err := ca.begin(ctx, OpDNSChallenges); err != nil {
		return nil, err
	}
	ca.mu.Lock()
	defer ca.mu.Unlock()
	o, ok := ca.orders[order.URL]
	if !ok {
		return nil, ca.rejected(core.ProblemMalformed, "no such order")
	}
	var out []core.UpstreamChallenge
	for _, a := range o.authzs {
		switch a.status {
		case "valid":
			continue
		case "invalid":
			return nil, ca.rejected(core.ProblemUnauthorized, "authorization for %s is invalid", a.identifier)
		}
		out = append(out, core.UpstreamChallenge{AuthorizationURL: a.url, URL: a.chURL, Identifier: a.identifier,
			Wildcard: a.wildcard, RecordName: names.ChallengeRecord(a.identifier), Value: a.value})
	}
	return out, nil
}

// Accept implements core.Provider. Validation happens here, once: if the
// expected TXT value is not visible the authorization and the order become
// invalid (Accept itself still returns nil, as a real CA would; WaitReady
// reports the failure).
func (ca *FakeCA) Accept(ctx context.Context, ch core.UpstreamChallenge) error {
	if _, err := ca.begin(ctx, OpAccept); err != nil {
		return err
	}
	ca.mu.Lock()
	var o *caOrder
	var a *caAuthz
	for _, cand := range ca.orderList {
		for _, az := range cand.authzs {
			if az.chURL == ch.URL {
				o, a = cand, az
			}
		}
	}
	if a == nil {
		ca.mu.Unlock()
		return ca.rejected(core.ProblemMalformed, "no such challenge")
	}
	if a.status != "pending" {
		ca.mu.Unlock()
		return nil
	}
	lookup, record, want := ca.lookup, names.ChallengeRecord(a.identifier), a.value
	ca.mu.Unlock()

	ok, detail := true, ""
	if lookup != nil {
		values, err := lookup(ctx, record)
		switch {
		case err != nil:
			ok, detail = false, "DNS problem looking up TXT for "+record
		case !slices.Contains(values, want):
			ok, detail = false, "incorrect TXT record found at "+record
		}
	}

	ca.mu.Lock()
	defer ca.mu.Unlock()
	if a.status != "pending" {
		return nil
	}
	if !ok {
		a.status = "invalid"
		o.status = core.UpstreamInvalid
		o.problem = core.NewProblem(core.ProblemUnauthorized, "%s", detail)
		return nil
	}
	a.status = "valid"
	if o.statusAt(ca.clock.Now()) == core.UpstreamPending {
		all := true
		for _, az := range o.authzs {
			all = all && az.status == "valid"
		}
		if all {
			o.status = core.UpstreamReady
		}
	}
	return nil
}

// WaitReady implements core.Provider. An order that is still pending (not
// every challenge accepted) is reported as a validation timeout
// (ProviderDown), which is what the real adapter does after waiting.
func (ca *FakeCA) WaitReady(ctx context.Context, orderURL string) (core.UpstreamOrder, error) {
	if _, err := ca.begin(ctx, OpWaitReady); err != nil {
		return core.UpstreamOrder{}, err
	}
	ca.mu.Lock()
	defer ca.mu.Unlock()
	o, ok := ca.orders[orderURL]
	if !ok {
		return core.UpstreamOrder{}, ca.rejected(core.ProblemMalformed, "no such order")
	}
	v := o.view(ca.clock.Now())
	switch v.Status {
	case core.UpstreamInvalid:
		return core.UpstreamOrder{}, &core.ProviderError{Provider: ca.name, Kind: core.ProviderRejected, Problem: v.Error}
	case core.UpstreamPending:
		return core.UpstreamOrder{}, &core.ProviderError{Provider: ca.name, Kind: core.ProviderDown,
			Err: fmt.Errorf("order %s still pending: validation timed out", orderURL)}
	}
	return v, nil
}

// Finalize implements core.Provider.
func (ca *FakeCA) Finalize(ctx context.Context, orderURL string, csrDER []byte) (core.UpstreamOrder, error) {
	after, err := ca.begin(ctx, OpFinalize)
	if err != nil {
		return core.UpstreamOrder{}, err
	}
	ca.mu.Lock()
	defer ca.mu.Unlock()
	now := ca.clock.Now()
	o, ok := ca.orders[orderURL]
	if !ok {
		return core.UpstreamOrder{}, ca.rejected(core.ProblemMalformed, "no such order")
	}
	hash := core.CSRHash(csrDER)
	switch o.statusAt(now) {
	case core.UpstreamReady:
	case core.UpstreamProcessing, core.UpstreamValid:
		if o.csrHash == hash {
			return o.view(now), nil
		}
		return core.UpstreamOrder{}, ca.rejected(core.ProblemOrderNotReady, "order was already finalized with another CSR")
	case core.UpstreamInvalid:
		return core.UpstreamOrder{}, &core.ProviderError{Provider: ca.name, Kind: core.ProviderRejected, Problem: o.view(now).Error}
	default:
		return core.UpstreamOrder{}, ca.rejected(core.ProblemOrderNotReady, "order is %s", o.statusAt(now))
	}

	csr, err := x509.ParseCertificateRequest(csrDER)
	if err != nil {
		return core.UpstreamOrder{}, ca.rejected(core.ProblemBadCSR, "cannot parse CSR")
	}
	if err := csr.CheckSignature(); err != nil {
		return core.UpstreamOrder{}, ca.rejected(core.ProblemBadCSR, "CSR signature is invalid")
	}
	if len(csr.IPAddresses)+len(csr.EmailAddresses)+len(csr.URIs) > 0 {
		return core.UpstreamOrder{}, ca.rejected(core.ProblemBadCSR, "CSR contains non-DNS names")
	}
	raw := slices.Clone(csr.DNSNames)
	if csr.Subject.CommonName != "" {
		raw = append(raw, csr.Subject.CommonName)
	}
	csrSet, err := names.NewSet(raw...)
	if err != nil || !slices.Equal(csrSet.Names(), o.names) {
		return core.UpstreamOrder{}, ca.rejected(core.ProblemBadCSR, "CSR names do not match the order")
	}

	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 120))
	serial.Add(serial, big.NewInt(1))
	notBefore := now.Truncate(time.Second)
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: o.names[0]},
		DNSNames:     o.names,
		NotBefore:    notBefore,
		NotAfter:     notBefore.Add(ca.lifetime),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.inter, csr.PublicKey, ca.interKey)
	if err != nil {
		return core.UpstreamOrder{}, ca.rejected(core.ProblemBadPublicKey, "cannot sign: %v", err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		panic(err)
	}
	id, err := core.ARICertID(leaf)
	if err != nil {
		panic(err)
	}
	o.chain = append(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ca.inter.Raw})...)
	o.csrHash = hash
	o.certID = id
	o.status = core.UpstreamValid
	ca.certs[id] = &caCert{id: id, cert: leaf, names: slices.Clone(o.names)}
	ca.stats.Finalizations++
	ca.stats.CertificatesIssued++
	if after != nil {
		return core.UpstreamOrder{}, after
	}
	return o.view(now), nil
}

// WaitCertificate implements core.Provider.
func (ca *FakeCA) WaitCertificate(ctx context.Context, orderURL string) ([]byte, error) {
	if _, err := ca.begin(ctx, OpWaitCertificate); err != nil {
		return nil, err
	}
	ca.mu.Lock()
	defer ca.mu.Unlock()
	o, ok := ca.orders[orderURL]
	if !ok {
		return nil, ca.rejected(core.ProblemMalformed, "no such order")
	}
	now := ca.clock.Now()
	switch o.statusAt(now) {
	case core.UpstreamValid:
		return slices.Clone(o.chain), nil
	case core.UpstreamInvalid:
		return nil, &core.ProviderError{Provider: ca.name, Kind: core.ProviderRejected, Problem: o.view(now).Error}
	}
	return nil, ca.rejected(core.ProblemOrderNotReady, "order is %s and was not finalized", o.statusAt(now))
}

// windowOf returns the suggested window: the override if set, else two days
// starting at two thirds of the certificate's lifetime.
func (ca *FakeCA) windowOf(c *caCert) (start, end time.Time) {
	if !c.windowStart.IsZero() || !c.windowEnd.IsZero() {
		return c.windowStart, c.windowEnd
	}
	life := c.cert.NotAfter.Sub(c.cert.NotBefore)
	start = c.cert.NotBefore.Add(life * 2 / 3)
	end = start.Add(48 * time.Hour)
	if end.After(c.cert.NotAfter) {
		end = c.cert.NotAfter
	}
	return start, end
}

// RenewalInfo implements core.Provider. RetryAfter is always 6 hours.
func (ca *FakeCA) RenewalInfo(ctx context.Context, ariCertID string) (core.RenewalInfo, error) {
	if _, err := ca.begin(ctx, OpRenewalInfo); err != nil {
		return core.RenewalInfo{}, err
	}
	ca.mu.Lock()
	defer ca.mu.Unlock()
	if !ca.caps.ARI {
		return core.RenewalInfo{}, ca.rejected(core.ProblemMalformed, "this CA does not serve renewal information")
	}
	c, ok := ca.certs[ariCertID]
	if !ok {
		return core.RenewalInfo{}, ca.rejected(core.ProblemMalformed, "unknown certificate")
	}
	start, end := ca.windowOf(c)
	return core.RenewalInfo{WindowStart: start, WindowEnd: end, RetryAfter: 6 * time.Hour}, nil
}

// SerialHex returns a certificate serial as core.Certificate.Serial expects
// it: lowercase hex without leading zeros.
func SerialHex(c *x509.Certificate) string {
	s := strings.TrimLeft(hex.EncodeToString(c.SerialNumber.Bytes()), "0")
	if s == "" {
		return "0"
	}
	return s
}
