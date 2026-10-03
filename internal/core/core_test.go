package core

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"net/netip"
	"testing"
	"time"

	"tls-broker/internal/names"
)

func TestIDsAndHashes(t *testing.T) {
	a, b := NewID(), NewID()
	if a == b || len(a) != 22 {
		t.Fatalf("NewID: %q %q", a, b)
	}
	tok := NewToken()
	if len(tok) != 43 || tok == NewToken() {
		t.Fatalf("NewToken: %q", tok)
	}
	if h := HashToken("abc"); h != "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad" {
		t.Fatalf("HashToken = %s", h)
	}
	if CSRHash([]byte("abc")) != HashToken("abc") {
		t.Fatal("CSRHash must be hex sha256")
	}
}

func TestARICertID(t *testing.T) {
	// Example from RFC 9773 §4.1: AKI 69:88:5B:6B:87:46:40:41:E1:B3:7B:84:7B:A0:AE:2C:DE:01:C8:D4,
	// serial 00:87:65:43:21.
	cert := &x509.Certificate{
		AuthorityKeyId: []byte{0x69, 0x88, 0x5B, 0x6B, 0x87, 0x46, 0x40, 0x41, 0xE1, 0xB3, 0x7B, 0x84, 0x7B, 0xA0, 0xAE, 0x2C, 0xDE, 0x01, 0xC8, 0xD4},
		SerialNumber:   big.NewInt(0x87654321),
	}
	got, err := ARICertID(cert)
	if err != nil {
		t.Fatal(err)
	}
	if want := "aYhba4dGQEHhs3uEe6CuLN4ByNQ.AIdlQyE"; got != want {
		t.Fatalf("ARICertID = %q, want %q", got, want)
	}
	if _, err := ARICertID(&x509.Certificate{SerialNumber: big.NewInt(1)}); err == nil {
		t.Fatal("certificate without AKI must fail")
	}

	// A real certificate round-trips through parsing.
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(255), Subject: pkix.Name{CommonName: "ca"},
		NotBefore: time.Now(), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true,
		SubjectKeyId: []byte{1, 2, 3}, AuthorityKeyId: []byte{1, 2, 3}}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	parsed, _ := x509.ParseCertificate(der)
	got, err = ARICertID(parsed)
	if err != nil || got != "AQID.AP8" {
		t.Fatalf("ARICertID(parsed) = %q, %v", got, err)
	}
}

func TestRoles(t *testing.T) {
	if !RoleAdmin.AtLeast(RoleWildcardAllowed) || !RoleWildcardAllowed.AtLeast(RoleNormal) || !RoleNormal.AtLeast(RoleNormal) {
		t.Fatal("role hierarchy broken")
	}
	if RoleNormal.AtLeast(RoleWildcardAllowed) || RoleWildcardAllowed.AtLeast(RoleAdmin) {
		t.Fatal("lower role passes for higher")
	}
	if Role("root").Valid() || Role("root").AtLeast(RoleNormal) || Role("").AtLeast(Role("")) {
		t.Fatal("invalid role accepted")
	}
	admin := &User{Role: RoleAdmin}
	if !admin.Can(RoleAdmin) {
		t.Fatal("admin cannot admin")
	}
	admin.Blocked = true
	if admin.Can(RoleNormal) || admin.EffectiveRole() != "" {
		t.Fatal("blocked admin keeps rights")
	}
	var nobody *User
	if nobody.Can(RoleNormal) {
		t.Fatal("nil user has rights")
	}
}

func TestStateHelpers(t *testing.T) {
	if OrderReady.Terminal() || OrderProcessing.Terminal() || !OrderValid.Terminal() || !OrderInvalid.Terminal() {
		t.Fatal("OrderStatus.Terminal wrong")
	}
	wants := map[ChallengeState]bool{ChallengePending: true, ChallengePresenting: true, ChallengeWaitingDNS: true,
		ChallengeReady: true, ChallengeCleaning: false, ChallengeDone: false, ChallengeFailed: false}
	for s, w := range wants {
		if s.WantsRecord() != w {
			t.Errorf("%s.WantsRecord() = %v", s, !w)
		}
		if s.Terminal() != (s == ChallengeDone || s == ChallengeFailed) {
			t.Errorf("%s.Terminal() wrong", s)
		}
	}
	for c := ClassARIRenewal; c <= ClassDirectBackground; c++ {
		if !c.Valid() || c.String() == "unknown" {
			t.Errorf("class %d not valid/named", c)
		}
	}
	if PriorityClass(0).Valid() || PriorityClass(7).Valid() || PriorityClass(7).String() != "unknown" {
		t.Fatal("out-of-range class accepted")
	}
	if !(&Order{CSRHash: "x"}).Finalized() || (&Order{}).Finalized() {
		t.Fatal("Order.Finalized wrong")
	}
	if OrderOwner("abc") != "order:abc" || DNSProxyOwner(netip.MustParseAddr("10.0.0.7")) != "dnsproxy:10.0.0.7" {
		t.Fatal("owner helpers changed")
	}
}

func TestProviderStateOpenAt(t *testing.T) {
	now := time.Date(2026, 10, 2, 12, 0, 0, 0, time.UTC)
	if !(ProviderState{}).OpenAt(now) || !(ProviderState{Health: ProviderHealthy, RetryAfter: now.Add(time.Hour)}).OpenAt(now) {
		t.Fatal("healthy provider must be open")
	}
	s := ProviderState{Health: ProviderUnavailable, RetryAfter: now.Add(time.Minute)}
	if s.OpenAt(now) {
		t.Fatal("down provider open before RetryAfter")
	}
	if !s.OpenAt(now.Add(time.Minute)) {
		t.Fatal("provider must reopen at RetryAfter")
	}
}

func TestLineageObserve(t *testing.T) {
	t0 := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	def := 24 * time.Hour
	l := Lineage{Key: "a.example.com"}
	if l.Interval(def) != def {
		t.Fatal("empty lineage must use the default")
	}
	l = l.Observe(t0)
	if l.Samples != 0 || !l.LastRequestAt.Equal(t0) || l.Interval(def) != def {
		t.Fatalf("after first request: %+v", l)
	}
	// A burst inside MinLineageGap is one visit and keeps the anchor.
	l = l.Observe(t0.Add(10 * time.Minute))
	if l.Samples != 0 || !l.LastRequestAt.Equal(t0) {
		t.Fatalf("burst counted: %+v", l)
	}
	// Out-of-order request is ignored.
	l = l.Observe(t0.Add(-time.Hour))
	if l.Samples != 0 || !l.LastRequestAt.Equal(t0) {
		t.Fatalf("earlier request counted: %+v", l)
	}
	l = l.Observe(t0.Add(12 * time.Hour))
	if l.Samples != 1 || l.ObservedInterval != 12*time.Hour || l.Interval(def) != 12*time.Hour {
		t.Fatalf("first sample: %+v", l)
	}
	l = l.Observe(t0.Add(12*time.Hour + 20*time.Hour))
	if want := (3*12*time.Hour + 20*time.Hour) / 4; l.Samples != 2 || l.ObservedInterval != want {
		t.Fatalf("second sample: %+v, want interval %s", l, want)
	}
	if l.Key != "a.example.com" {
		t.Fatal("key lost")
	}
}

func TestEmergencyWindow(t *testing.T) {
	cfg := DefaultConfig().Emergency
	day := 24 * time.Hour
	// The two worked examples of architecture §8.
	if got := EmergencyWindow(cfg, 90*day, day); got != 7*day+12*time.Hour {
		t.Fatalf("daily checks: %s", got)
	}
	if got := EmergencyWindow(cfg, 90*day, 7*day); got != 25*day+12*time.Hour {
		t.Fatalf("weekly checks: %s", got)
	}
	// Capped at half the lifetime.
	if got := EmergencyWindow(cfg, 90*day, 30*day); got != 45*day {
		t.Fatalf("cap: %s", got)
	}
	if got := EmergencyWindow(cfg, 6*day, day); got != 3*day {
		t.Fatalf("short-lived cap: %s", got)
	}
	if got := EmergencyWindow(EmergencyConfig{Fraction: -1}, day, 0); got != 0 {
		t.Fatalf("negative window: %s", got)
	}
}

func TestRenewalInfoWindow(t *testing.T) {
	s := time.Date(2026, 3, 1, 0, 0, 0, 0, time.UTC)
	ri := RenewalInfo{WindowStart: s, WindowEnd: s.Add(48 * time.Hour)}
	cases := []struct {
		at      time.Time
		in, due bool
	}{
		{s.Add(-time.Second), false, false},
		{s, true, true},
		{s.Add(47 * time.Hour), true, true},
		{s.Add(48 * time.Hour), false, true},
	}
	for _, c := range cases {
		if ri.InWindow(c.at) != c.in || ri.Due(c.at) != c.due {
			t.Errorf("at %s: InWindow=%v Due=%v", c.at, ri.InWindow(c.at), ri.Due(c.at))
		}
	}
}

func TestProblemJSONAndStatus(t *testing.T) {
	p := NewProblem(ProblemRateLimited, "too many for %s", "example.com").WithRetryAfter(time.Minute)
	if p.Status != http.StatusTooManyRequests || p.RetryAfter != time.Minute {
		t.Fatalf("problem = %+v", p)
	}
	b, err := json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	want := `{"type":"urn:ietf:params:acme:error:rateLimited","detail":"too many for example.com","status":429}`
	if string(b) != want {
		t.Fatalf("JSON = %s\nwant   %s", b, want)
	}
	var back Problem
	if err := json.Unmarshal(b, &back); err != nil || back.Type != p.Type || back.Detail != p.Detail || back.Status != 429 {
		t.Fatalf("round trip: %+v, %v", back, err)
	}
	if p.Error() != "rateLimited: too many for example.com" {
		t.Fatalf("Error() = %q", p.Error())
	}
	sub := &Problem{Type: ProblemRejectedIdentifier, Subproblems: []Subproblem{{Type: ProblemRejectedIdentifier,
		Identifier: &ProblemIdentifier{Type: "dns", Value: "x.example.com"}}}}
	b, _ = json.Marshal(sub)
	if string(b) != `{"type":"urn:ietf:params:acme:error:rejectedIdentifier","subproblems":[{"type":"urn:ietf:params:acme:error:rejectedIdentifier","identifier":{"type":"dns","value":"x.example.com"}}]}` {
		t.Fatalf("subproblem JSON = %s", b)
	}
	statuses := map[string]int{ProblemMalformed: 400, ProblemBadCSR: 400, ProblemBadNonce: 400, ProblemUnauthorized: 403,
		ProblemOrderNotReady: 403, ProblemAlreadyReplaced: 409, ProblemRateLimited: 429, ProblemServerInternal: 500,
		ProblemAccountDoesNotExist: 400, "urn:example:unknown": 500}
	for typ, st := range statuses {
		if ProblemStatus(typ) != st {
			t.Errorf("ProblemStatus(%s) = %d, want %d", typ, ProblemStatus(typ), st)
		}
	}
	wrapped := fmt.Errorf("ctx: %w", p)
	if AsProblem(wrapped) != p || !errors.Is(wrapped, &Problem{Type: ProblemRateLimited}) || errors.Is(wrapped, &Problem{Type: ProblemBadCSR}) {
		t.Fatal("AsProblem / errors.Is on wrapped problem")
	}
	if q := p.WithStatus(503); q.Status != 503 || p.Status != 429 {
		t.Fatal("WithStatus must copy")
	}
}

func TestProblemFromError(t *testing.T) {
	_, nameErr := names.Normalize("bad_name.example.com")
	cases := []struct {
		name   string
		err    error
		typ    string
		status int
		retry  time.Duration
	}{
		{"problem", fmt.Errorf("w: %w", NewProblem(ProblemBadCSR, "x")), ProblemBadCSR, 400, 0},
		{"admission rate", &AdmissionError{Kind: AdmissionRateLimited, RetryAfter: time.Hour, Reason: "r"}, ProblemRateLimited, 429, time.Hour},
		{"admission busy", &AdmissionError{Kind: AdmissionBusy, RetryAfter: 30 * time.Second}, ProblemRateLimited, 429, 30 * time.Second},
		{"admission down", &AdmissionError{Kind: AdmissionProviderDown, RetryAfter: time.Minute}, ProblemServerInternal, 503, time.Minute},
		{"provider rate", &ProviderError{Provider: "le", Kind: ProviderRateLimited, RetryAfter: 2 * time.Hour}, ProblemRateLimited, 429, 2 * time.Hour},
		{"provider busy", &ProviderError{Provider: "le", Kind: ProviderBusy, RetryAfter: time.Minute}, ProblemServerInternal, 503, time.Minute},
		{"provider down", fmt.Errorf("w: %w", &ProviderError{Provider: "le", Kind: ProviderDown, Err: errors.New("dial tcp 10.1.2.3: refused")}), ProblemServerInternal, 503, 0},
		{"provider rejected with problem", &ProviderError{Provider: "le", Kind: ProviderRejected, Problem: NewProblem(ProblemCAA, "CAA forbids")}, ProblemCAA, 403, 0},
		{"provider rejected bare", &ProviderError{Provider: "le", Kind: ProviderRejected}, ProblemServerInternal, 500, 0},
		{"name", nameErr, ProblemRejectedIdentifier, 400, 0},
		{"empty set", names.ErrEmptySet, ProblemRejectedIdentifier, 400, 0},
		{"zone", fmt.Errorf("x: %w", ErrOutsideManagedZones), ProblemRejectedIdentifier, 400, 0},
		{"csr mismatch", ErrCSRMismatch, ProblemBadCSR, 400, 0},
		{"not found", ErrNotFound, ProblemMalformed, 404, 0},
		{"expired", ErrExpired, ProblemMalformed, 404, 0},
		{"other", errors.New("sql: database is locked at /data/state.db"), ProblemServerInternal, 500, 0},
		{"context", context.DeadlineExceeded, ProblemServerInternal, 500, 0},
	}
	for _, c := range cases {
		p := ProblemFromError(c.err)
		if p == nil || p.Type != c.typ || p.Status != c.status || p.RetryAfter != c.retry {
			t.Errorf("%s: got %+v, want type %s status %d retry %s", c.name, p, c.typ, c.status, c.retry)
		}
	}
	if ProblemFromError(nil) != nil {
		t.Fatal("nil error must give nil problem")
	}
	// Internal text must not leak.
	for _, err := range []error{errors.New("secret path /data/state.db"), &ProviderError{Kind: ProviderDown, Err: errors.New("10.1.2.3 refused")}} {
		if d := ProblemFromError(err).Detail; d == "" || containsAny(d, "/data", "10.1.2.3") {
			t.Errorf("detail leaks internals: %q", d)
		}
	}
}

func containsAny(s string, subs ...string) bool {
	for _, sub := range subs {
		for i := 0; i+len(sub) <= len(s); i++ {
			if s[i:i+len(sub)] == sub {
				return true
			}
		}
	}
	return false
}

func TestErrorTypes(t *testing.T) {
	inner := errors.New("boom")
	pe := &ProviderError{Provider: "le", Kind: ProviderDown, Err: inner, RetryAfter: time.Minute}
	wrapped := fmt.Errorf("new order: %w", pe)
	if AsProviderError(wrapped) != pe || !errors.Is(wrapped, inner) {
		t.Fatal("ProviderError unwrap chain broken")
	}
	if AsProviderError(inner) != nil || AsAdmissionError(inner) != nil || AsProblem(inner) != nil {
		t.Fatal("As* on a foreign error must be nil")
	}
	health := map[ProviderErrorKind]bool{ProviderRateLimited: true, ProviderBusy: true, ProviderDown: true,
		ProviderRejected: false, ProviderAlreadyReplaced: false}
	for k, w := range health {
		if (&ProviderError{Kind: k}).AffectsHealth() != w {
			t.Errorf("%s AffectsHealth != %v", k, w)
		}
	}
	if pe.Error() == "" || (&AdmissionError{Kind: AdmissionBusy}).Error() == "" {
		t.Fatal("empty error text")
	}
	ae := &AdmissionError{Kind: AdmissionBusy, RetryAfter: time.Second}
	if AsAdmissionError(fmt.Errorf("x: %w", ae)) != ae {
		t.Fatal("AsAdmissionError")
	}
}

func TestConfigHelpers(t *testing.T) {
	c := DefaultConfig()
	if c.Scheduler.AdmitWait != 20*time.Second || c.Scheduler.FinalizeWait != 20*time.Second || c.Scheduler.OrderTTL != 15*time.Minute {
		t.Fatal("scheduler defaults differ from architecture §7")
	}
	if c.Emergency.Fraction != 0.05 || c.Emergency.SafetyChecks != 3 || c.Emergency.DefaultInterval != 24*time.Hour {
		t.Fatal("emergency defaults differ from architecture §8")
	}
	c.Zones = []ZoneConfig{{Name: "example.com", HostedZoneID: "Z1"}, {Name: "corp.example.com", HostedZoneID: "Z2"}, {Name: "bad zone", HostedZoneID: "Z3"}}
	z, ok := c.ZoneFor("a.corp.example.com")
	if !ok || z.HostedZoneID != "Z2" {
		t.Fatalf("ZoneFor longest suffix: %+v %v", z, ok)
	}
	z, ok = c.ZoneFor("*.example.com")
	if !ok || z.HostedZoneID != "Z1" {
		t.Fatalf("ZoneFor wildcard: %+v %v", z, ok)
	}
	if _, ok := c.ZoneFor("a.example.net"); ok {
		t.Fatal("ZoneFor outside zone")
	}
	if got := c.ManagedZones().List(); len(got) != 2 {
		t.Fatalf("ManagedZones = %v", got)
	}
	c.Providers = []ProviderConfig{{Name: "le"}, {Name: "old", Disabled: true}, {Name: "gts"}}
	if p, ok := c.Provider("old"); !ok || !p.Disabled {
		t.Fatal("Provider must return disabled providers")
	}
	if _, ok := c.Provider("nope"); ok {
		t.Fatal("unknown provider found")
	}
	en := c.EnabledProviders()
	if len(en) != 2 || en[0].Name != "le" || en[1].Name != "gts" {
		t.Fatalf("EnabledProviders = %+v", en)
	}
	if c.TrustsProxy(netip.MustParseAddr("127.0.0.1")) {
		t.Fatal("no proxy is trusted by default")
	}
	c.Server.TrustedProxies = []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8")}
	if !c.TrustsProxy(netip.MustParseAddr("127.0.0.1")) || !c.TrustsProxy(netip.MustParseAddr("::ffff:127.0.0.1")) || c.TrustsProxy(netip.MustParseAddr("10.0.0.1")) {
		t.Fatal("TrustsProxy wrong")
	}
	l := DefaultProviderLimits()
	if l.Concurrency < 1 || l.NewOrders.Count >= 300 || l.CertsPerDomain.Count >= 50 || l.CertsPerSet.Count >= 5 {
		t.Fatalf("default limits must stay below Let's Encrypt's: %+v", l)
	}
	if !(ConfigCheck{Warnings: []string{"w"}}).OK() || (ConfigCheck{Errors: []string{"e"}}).OK() {
		t.Fatal("ConfigCheck.OK")
	}
}

func TestSystemClockAndSleep(t *testing.T) {
	var c Clock = SystemClock{}
	if c.Now().Location() != time.UTC {
		t.Fatal("SystemClock must be UTC")
	}
	if err := Sleep(context.Background(), c, time.Millisecond); err != nil {
		t.Fatal(err)
	}
	if err := Sleep(context.Background(), c, 0); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := Sleep(ctx, c, time.Hour); !errors.Is(err, context.Canceled) {
		t.Fatalf("Sleep on cancelled ctx: %v", err)
	}
}
