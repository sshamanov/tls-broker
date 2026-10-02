package coretest

import (
	"context"
	"crypto/rsa"
	"encoding/pem"
	"errors"
	"reflect"
	"slices"
	"testing"
	"time"

	"tls-broker/internal/core"
)

// issue drives a whole issuance through the Provider interface the way the
// engine will, publishing TXT values through the DNS engine.
func issue(t *testing.T, ca *FakeCA, dns *FakeDNSEngine, replaces string, dnsNames ...string) (core.UpstreamOrder, []byte) {
	t.Helper()
	order, err := ca.NewOrder(ctx, dnsNames, replaces)
	if err != nil {
		t.Fatalf("NewOrder: %v", err)
	}
	chs, err := ca.DNSChallenges(ctx, order)
	if err != nil {
		t.Fatalf("DNSChallenges: %v", err)
	}
	for _, ch := range chs {
		if _, err := dns.Present(ctx, core.OrderOwner(order.URL), ch.RecordName, ch.Value); err != nil {
			t.Fatalf("Present: %v", err)
		}
		if err := ca.Accept(ctx, ch); err != nil {
			t.Fatalf("Accept: %v", err)
		}
	}
	if _, err := ca.WaitReady(ctx, order.URL); err != nil {
		t.Fatalf("WaitReady: %v", err)
	}
	_ = dns.CleanupOwner(ctx, core.OrderOwner(order.URL))
	order, err = ca.Finalize(ctx, order.URL, MakeCSR(GenKey(), dnsNames...))
	if err != nil {
		t.Fatalf("Finalize: %v", err)
	}
	chain, err := ca.WaitCertificate(ctx, order.URL)
	if err != nil {
		t.Fatalf("WaitCertificate: %v", err)
	}
	return order, chain
}

func newCA(t *testing.T) (*FakeCA, *FakeDNSEngine, *FakeResolver, *FakeClock) {
	t.Helper()
	clock := NewFakeClock()
	res := NewFakeResolver()
	ca := NewFakeCA("primary", clock)
	ca.SetTXTLookup(res.LookupTXT)
	return ca, NewFakeDNSEngine(res, clock), res, clock
}

func kind(err error) core.ProviderErrorKind {
	if pe := core.AsProviderError(err); pe != nil {
		return pe.Kind
	}
	return ""
}

func TestFakeCAIssuesRealCertificates(t *testing.T) {
	ca, dns, res, clock := newCA(t)
	url, err := ca.AccountURL(ctx)
	if err != nil || url != "https://primary.test/acme/acct/1" {
		t.Fatalf("AccountURL = %q, %v", url, err)
	}
	_, _ = ca.AccountURL(ctx)

	order, chain := issue(t, ca, dns, "", "B.example.com", "a.example.com", "*.example.com")
	if order.Status != core.UpstreamValid || order.CertificateURL == "" {
		t.Fatalf("order = %+v", order)
	}
	if !reflect.DeepEqual(order.Names, []string{"*.example.com", "a.example.com", "b.example.com"}) {
		t.Fatalf("order names = %v", order.Names)
	}
	certs, err := ParseChain(chain)
	if err != nil || len(certs) != 2 {
		t.Fatalf("chain must be leaf + intermediate: %d, %v", len(certs), err)
	}
	for _, n := range []string{"a.example.com", "b.example.com", "x.example.com"} {
		if _, err := ca.VerifyChain(chain, n); err != nil {
			t.Errorf("VerifyChain(%s): %v", n, err)
		}
	}
	if _, err := ca.VerifyChain(chain, "a.example.org"); err == nil {
		t.Error("chain verified for a foreign name")
	}
	leaf := certs[0]
	if !leaf.NotBefore.Equal(clock.Now()) || leaf.NotAfter.Sub(leaf.NotBefore) != 90*24*time.Hour {
		t.Fatalf("validity %s..%s", leaf.NotBefore, leaf.NotAfter)
	}
	if id, err := core.ARICertID(leaf); err != nil || id == "" {
		t.Fatalf("ARICertID: %q, %v", id, err)
	}
	if SerialHex(leaf) == "" {
		t.Fatal("SerialHex")
	}
	// A chain from another CA does not verify.
	other := NewFakeCA("fallback", clock)
	if _, err := other.VerifyChain(chain, ""); err == nil {
		t.Fatal("chain verified against a different CA")
	}
	// A chain that includes the root is refused by the helper.
	if _, err := ca.VerifyChain(append(slices.Clone(chain), ca.RootPEM()...), ""); err == nil {
		t.Fatal("chain with root accepted")
	}
	// Expiry is judged on the fake clock.
	clock.Advance(91 * 24 * time.Hour)
	if _, err := ca.VerifyChain(chain, ""); err == nil {
		t.Fatal("expired chain verified")
	}

	st := ca.Stats()
	if st.AccountsRegistered != 1 || st.OrdersCreated != 1 || st.Finalizations != 1 || st.CertificatesIssued != 1 || st.ExemptOrders != 0 {
		t.Fatalf("stats = %+v", st)
	}
	if st.Calls[OpNewOrder] != 1 || st.Calls[OpAccept] != 3 || st.Calls[OpAccountURL] != 2 {
		t.Fatalf("calls = %+v", st.Calls)
	}
	if n := len(res.txt); n != 0 {
		t.Fatalf("%d TXT records left after cleanup", n)
	}
}

func TestFakeCAWildcardAndBaseShareRecord(t *testing.T) {
	ca, _, _, _ := newCA(t)
	order, _ := ca.NewOrder(ctx, []string{"example.com", "*.example.com"}, "")
	chs, err := ca.DNSChallenges(ctx, order)
	if err != nil || len(chs) != 2 {
		t.Fatalf("challenges = %+v, %v", chs, err)
	}
	if chs[0].RecordName != "_acme-challenge.example.com" || chs[1].RecordName != chs[0].RecordName {
		t.Fatalf("record names: %q, %q", chs[0].RecordName, chs[1].RecordName)
	}
	if chs[0].Value == chs[1].Value {
		t.Fatal("wildcard and base must need two different values at one record")
	}
	if !chs[0].Wildcard || chs[1].Wildcard || chs[0].Identifier != "example.com" {
		t.Fatalf("wildcard flags: %+v", chs)
	}
}

func TestFakeCAValidationNeedsTXT(t *testing.T) {
	ca, dns, res, _ := newCA(t)
	order, _ := ca.NewOrder(ctx, []string{"a.example.com", "b.example.com"}, "")
	chs, _ := ca.DNSChallenges(ctx, order)

	// Nothing accepted yet: WaitReady reports a validation timeout.
	if _, err := ca.WaitReady(ctx, order.URL); kind(err) != core.ProviderDown {
		t.Fatalf("WaitReady on a pending order: %v", err)
	}
	// First challenge presented and accepted; the order stays pending.
	_, _ = dns.Present(ctx, "o", chs[0].RecordName, chs[0].Value)
	if err := ca.Accept(ctx, chs[0]); err != nil {
		t.Fatal(err)
	}
	left, _ := ca.DNSChallenges(ctx, order)
	if len(left) != 1 || left[0].Identifier != chs[1].Identifier {
		t.Fatalf("valid authorizations must be omitted: %+v", left)
	}
	if got, _ := ca.GetOrder(ctx, order.URL); got.Status != core.UpstreamPending {
		t.Fatalf("status = %s", got.Status)
	}
	// Accepting again is a no-op.
	res.RemoveTXT(chs[0].RecordName, chs[0].Value)
	if err := ca.Accept(ctx, chs[0]); err != nil {
		t.Fatal(err)
	}
	// Second challenge accepted with a wrong value published: the CA
	// validates once and the order is dead.
	res.AddTXT(chs[1].RecordName, "wrong")
	if err := ca.Accept(ctx, chs[1]); err != nil {
		t.Fatalf("Accept returns nil even when validation fails: %v", err)
	}
	_, err := ca.WaitReady(ctx, order.URL)
	if pe := core.AsProviderError(err); pe == nil || pe.Kind != core.ProviderRejected || pe.Problem == nil || pe.Problem.Type != core.ProblemUnauthorized {
		t.Fatalf("WaitReady after failed validation: %v", err)
	}
	if got, _ := ca.GetOrder(ctx, order.URL); got.Status != core.UpstreamInvalid || got.Error == nil {
		t.Fatalf("order = %+v", got)
	}
	if _, err := ca.DNSChallenges(ctx, order); kind(err) != core.ProviderRejected {
		t.Fatalf("DNSChallenges on an invalid authorization: %v", err)
	}
	if _, err := ca.Finalize(ctx, order.URL, MakeCSR(GenKey(), "a.example.com", "b.example.com")); kind(err) != core.ProviderRejected {
		t.Fatalf("Finalize on an invalid order: %v", err)
	}
	if ca.Stats().CertificatesIssued != 0 {
		t.Fatal("certificate issued without validation")
	}

	// A resolver failure during validation also fails the order.
	order2, _ := ca.NewOrder(ctx, []string{"c.example.com"}, "")
	chs2, _ := ca.DNSChallenges(ctx, order2)
	res.FailAll(core.ErrResolver)
	_ = ca.Accept(ctx, chs2[0])
	res.FailAll(nil)
	if _, err := ca.WaitReady(ctx, order2.URL); kind(err) != core.ProviderRejected {
		t.Fatalf("validation with failing DNS: %v", err)
	}
	if err := ca.Accept(ctx, core.UpstreamChallenge{URL: "https://primary.test/nope"}); kind(err) != core.ProviderRejected {
		t.Fatalf("Accept of an unknown challenge: %v", err)
	}
}

func TestFakeCAWithoutLookupValidatesEverything(t *testing.T) {
	ca := NewFakeCA("primary", NewFakeClock())
	order, _ := ca.NewOrder(ctx, []string{"a.example.com"}, "")
	chs, _ := ca.DNSChallenges(ctx, order)
	_ = ca.Accept(ctx, chs[0])
	if got, err := ca.WaitReady(ctx, order.URL); err != nil || got.Status != core.UpstreamReady {
		t.Fatalf("WaitReady = %+v, %v", got, err)
	}
}

func TestFakeCAFinalizeRules(t *testing.T) {
	ca, dns, _, _ := newCA(t)
	ready := func(dnsNames ...string) core.UpstreamOrder {
		order, _ := ca.NewOrder(ctx, dnsNames, "")
		chs, _ := ca.DNSChallenges(ctx, order)
		for _, ch := range chs {
			_, _ = dns.Present(ctx, "o", ch.RecordName, ch.Value)
			_ = ca.Accept(ctx, ch)
		}
		o, err := ca.WaitReady(ctx, order.URL)
		if err != nil {
			t.Fatal(err)
		}
		return o
	}
	key := GenKey()

	pending, _ := ca.NewOrder(ctx, []string{"p.example.com"}, "")
	if _, err := ca.Finalize(ctx, pending.URL, MakeCSR(key, "p.example.com")); kind(err) != core.ProviderRejected {
		t.Fatalf("Finalize on a pending order: %v", err)
	}
	if _, err := ca.WaitCertificate(ctx, pending.URL); kind(err) != core.ProviderRejected {
		t.Fatalf("WaitCertificate on an unfinalized order: %v", err)
	}

	o := ready("a.example.com", "b.example.com")
	bad := [][]byte{
		[]byte("garbage"),
		MakeCSR(key, "a.example.com"),
		MakeCSR(key, "a.example.com", "b.example.com", "c.example.com"),
		MakeCSR(key, "a.example.com", "x.example.com"),
	}
	for i, csr := range bad {
		_, err := ca.Finalize(ctx, o.URL, csr)
		if pe := core.AsProviderError(err); pe == nil || pe.Kind != core.ProviderRejected || pe.Problem.Type != core.ProblemBadCSR {
			t.Errorf("bad CSR %d: %v", i, err)
		}
	}
	if ca.Stats().Finalizations != 0 {
		t.Fatal("rejected CSRs were counted")
	}
	// Case and order of names in the CSR do not matter.
	csr := MakeCSR(key, "B.example.com", "a.example.com")
	done, err := ca.Finalize(ctx, o.URL, csr)
	if err != nil || done.Status != core.UpstreamValid {
		t.Fatalf("Finalize: %+v, %v", done, err)
	}
	// Same CSR again: current state, no second issuance.
	again, err := ca.Finalize(ctx, o.URL, csr)
	if err != nil || again.Status != core.UpstreamValid {
		t.Fatalf("repeat Finalize: %+v, %v", again, err)
	}
	if _, err := ca.Finalize(ctx, o.URL, MakeCSR(GenKey(), "a.example.com", "b.example.com")); kind(err) != core.ProviderRejected {
		t.Fatalf("different CSR on a valid order: %v", err)
	}
	if st := ca.Stats(); st.Finalizations != 1 || st.CertificatesIssued != 1 {
		t.Fatalf("stats = %+v", st)
	}
	c1, _ := ca.WaitCertificate(ctx, o.URL)
	c2, _ := ca.WaitCertificate(ctx, o.URL)
	if string(c1) != string(c2) {
		t.Fatal("WaitCertificate must return the same chain every time")
	}

	// RSA keys work too and the leaf carries the CSR's key.
	rsaKey := GenRSAKey()
	o2 := ready("r.example.com")
	if _, err := ca.Finalize(ctx, o2.URL, MakeCSR(rsaKey, "r.example.com")); err != nil {
		t.Fatal(err)
	}
	chain, _ := ca.WaitCertificate(ctx, o2.URL)
	leaf, err := ca.VerifyChain(chain, "r.example.com")
	if err != nil {
		t.Fatal(err)
	}
	if pub, ok := leaf.PublicKey.(*rsa.PublicKey); !ok || !pub.Equal(&rsaKey.PublicKey) {
		t.Fatal("leaf does not carry the CSR's public key")
	}
	if b, _ := pem.Decode(chain); b == nil || b.Type != "CERTIFICATE" {
		t.Fatal("chain is not PEM")
	}

	for _, f := range []func() error{
		func() error { _, err := ca.GetOrder(ctx, "https://primary.test/none"); return err },
		func() error { _, err := ca.WaitReady(ctx, "https://primary.test/none"); return err },
		func() error { _, err := ca.Finalize(ctx, "https://primary.test/none", csr); return err },
		func() error { _, err := ca.WaitCertificate(ctx, "https://primary.test/none"); return err },
		func() error { _, err := ca.NewOrder(ctx, []string{"bad_name"}, ""); return err },
		func() error { _, err := ca.NewOrder(ctx, nil, ""); return err },
	} {
		if err := f(); kind(err) != core.ProviderRejected {
			t.Errorf("unknown order / bad names must be rejected: %v", err)
		}
	}
}

func TestFakeCAOrderExpiry(t *testing.T) {
	ca, _, _, clock := newCA(t)
	order, _ := ca.NewOrder(ctx, []string{"a.example.com"}, "")
	if !order.Expires.Equal(clock.Now().Add(7 * 24 * time.Hour)) {
		t.Fatalf("Expires = %s", order.Expires)
	}
	clock.Advance(7 * 24 * time.Hour)
	got, _ := ca.GetOrder(ctx, order.URL)
	if got.Status != core.UpstreamInvalid || got.Error == nil {
		t.Fatalf("expired order = %+v", got)
	}
	o2, _ := ca.NewOrder(ctx, []string{"b.example.com"}, "")
	if !ca.ExpireOrder(o2.URL) || ca.ExpireOrder("https://primary.test/none") {
		t.Fatal("ExpireOrder result")
	}
	if got, _ := ca.GetOrder(ctx, o2.URL); got.Status != core.UpstreamInvalid {
		t.Fatalf("ExpireOrder: %+v", got)
	}
	all := ca.Orders()
	if len(all) != 2 || all[0].URL != order.URL || all[1].Status != core.UpstreamInvalid {
		t.Fatalf("Orders = %+v", all)
	}
}

func TestFakeCARenewalInfoAndReplaces(t *testing.T) {
	ca, dns, _, clock := newCA(t)
	start := clock.Now()
	first, _ := issue(t, ca, dns, "", "a.example.com", "b.example.com")
	certID := ca.Orders()[0].CertID
	if certID == "" || first.Status != core.UpstreamValid {
		t.Fatal("no certificate")
	}

	ri, err := ca.RenewalInfo(ctx, certID)
	if err != nil {
		t.Fatal(err)
	}
	if !ri.WindowStart.Equal(start.Add(60*24*time.Hour)) || ri.WindowEnd.Sub(ri.WindowStart) != 48*time.Hour || ri.RetryAfter != 6*time.Hour {
		t.Fatalf("default renewal info = %+v", ri)
	}
	if _, err := ca.RenewalInfo(ctx, "unknown.id"); kind(err) != core.ProviderRejected {
		t.Fatalf("RenewalInfo for an unknown certificate: %v", err)
	}

	// replaces must name a certificate of this CA and share an identifier.
	if _, err := ca.NewOrder(ctx, []string{"a.example.com"}, "unknown.id"); kind(err) != core.ProviderRejected {
		t.Fatalf("replaces with an unknown certificate: %v", err)
	}
	if _, err := ca.NewOrder(ctx, []string{"z.example.com"}, certID); kind(err) != core.ProviderRejected {
		t.Fatalf("replaces without a shared identifier: %v", err)
	}
	created := ca.Stats().OrdersCreated

	// Outside the window: accepted, but not exempt.
	early, err := ca.NewOrder(ctx, []string{"a.example.com"}, certID)
	if err != nil || early.Replaces != certID {
		t.Fatalf("replaces outside the window: %+v, %v", early, err)
	}
	if ca.Stats().ExemptOrders != 0 || ca.Orders()[1].Exempt {
		t.Fatal("order outside the suggested window was exempt")
	}
	// One live replacement order per certificate.
	_, err = ca.NewOrder(ctx, []string{"a.example.com", "b.example.com"}, certID)
	if pe := core.AsProviderError(err); pe == nil || pe.Kind != core.ProviderAlreadyReplaced || pe.Problem.Type != core.ProblemAlreadyReplaced {
		t.Fatalf("second replacement order: %v", err)
	}
	if ca.Stats().OrdersCreated != created+1 {
		t.Fatal("a refused newOrder must not create an order")
	}
	// Once the first replacement order is dead the slot is free again.
	ca.ExpireOrder(early.URL)
	clock.Set(ri.WindowStart.Add(time.Hour))
	renewal, chain := issue(t, ca, dns, certID, "a.example.com", "b.example.com")
	if renewal.Replaces != certID {
		t.Fatalf("renewal = %+v", renewal)
	}
	if ca.Stats().ExemptOrders != 1 || !ca.Orders()[2].Exempt {
		t.Fatal("renewal inside the window must be exempt")
	}
	if _, err := ca.VerifyChain(chain, "a.example.com"); err != nil {
		t.Fatal(err)
	}
	// A finalized replacement keeps the predecessor replaced.
	if _, err := ca.NewOrder(ctx, []string{"a.example.com"}, certID); kind(err) != core.ProviderAlreadyReplaced {
		t.Fatalf("replacing an already replaced certificate: %v", err)
	}

	// The window can be overridden, and decides exemption.
	newID := ca.Orders()[2].CertID
	now := clock.Now()
	if !ca.SetRenewalWindow(newID, now.Add(-time.Hour), now.Add(time.Hour)) || ca.SetRenewalWindow("unknown.id", now, now) {
		t.Fatal("SetRenewalWindow result")
	}
	ri, _ = ca.RenewalInfo(ctx, newID)
	if !ri.InWindow(now) {
		t.Fatalf("overridden window = %+v", ri)
	}
	if _, err := ca.NewOrder(ctx, []string{"b.example.com"}, newID); err != nil {
		t.Fatal(err)
	}
	if ca.Stats().ExemptOrders != 2 {
		t.Fatal("order inside an overridden window must be exempt")
	}
}

func TestFakeCACapsWithoutARI(t *testing.T) {
	ca, dns, _, clock := newCA(t)
	_, _ = issue(t, ca, dns, "", "a.example.com")
	certID := ca.Orders()[0].CertID

	// A CA that serves ARI but does not exempt (Google Trust Services).
	caps := ca.Caps()
	caps.ARIExempt = false
	ca.SetCaps(caps)
	ri, _ := ca.RenewalInfo(ctx, certID)
	clock.Set(ri.WindowStart)
	o, err := ca.NewOrder(ctx, []string{"a.example.com"}, certID)
	if err != nil {
		t.Fatal(err)
	}
	if ca.Stats().ExemptOrders != 0 {
		t.Fatal("non-exempting CA reported an exempt order")
	}
	ca.ExpireOrder(o.URL)

	// A CA without ARI at all.
	caps.ARI = false
	ca.SetCaps(caps)
	if ca.Caps().ARI {
		t.Fatal("SetCaps")
	}
	if _, err := ca.RenewalInfo(ctx, certID); kind(err) != core.ProviderRejected {
		t.Fatalf("RenewalInfo without ARI: %v", err)
	}
	if _, err := ca.NewOrder(ctx, []string{"a.example.com"}, certID); kind(err) != core.ProviderRejected {
		t.Fatalf("replaces without ARI: %v", err)
	}
	// Caps returns a copy.
	c := ca.Caps()
	c.CAAIssuers[0] = "changed"
	if ca.Caps().CAAIssuers[0] != "primary.test" {
		t.Fatal("Caps must return a copy")
	}
}

func TestFakeCAFaults(t *testing.T) {
	ca, dns, _, clock := newCA(t)

	ca.Inject(Fault{Op: OpNewOrder, Err: ca.RateLimited(2 * time.Hour), Times: 2})
	for i := 0; i < 2; i++ {
		_, err := ca.NewOrder(ctx, []string{"a.example.com"}, "")
		if pe := core.AsProviderError(err); pe == nil || pe.Kind != core.ProviderRateLimited || pe.RetryAfter != 2*time.Hour {
			t.Fatalf("rate limited: %v", err)
		}
	}
	if ca.Stats().OrdersCreated != 0 {
		t.Fatal("a rate-limited newOrder must not create an order")
	}
	if _, err := ca.NewOrder(ctx, []string{"a.example.com"}, ""); err != nil {
		t.Fatalf("fault must wear off after Times calls: %v", err)
	}

	ca.Inject(Fault{Op: OpAny, Err: ca.Down()})
	if _, err := ca.AccountURL(ctx); kind(err) != core.ProviderDown {
		t.Fatalf("down AccountURL: %v", err)
	}
	if _, err := ca.RenewalInfo(ctx, "x"); kind(err) != core.ProviderDown {
		t.Fatalf("down RenewalInfo: %v", err)
	}
	if _, err := ca.GetOrder(ctx, "x"); kind(err) != core.ProviderDown {
		t.Fatalf("down GetOrder: %v", err)
	}
	ca.ClearFaults()

	ca.Inject(Fault{Op: OpFinalize, Err: ca.Busy(30 * time.Second), Times: 1})
	order, _ := ca.NewOrder(ctx, []string{"b.example.com"}, "")
	chs, _ := ca.DNSChallenges(ctx, order)
	_, _ = dns.Present(ctx, "o", chs[0].RecordName, chs[0].Value)
	_ = ca.Accept(ctx, chs[0])
	csr := MakeCSR(GenKey(), "b.example.com")
	_, err := ca.Finalize(ctx, order.URL, csr)
	if pe := core.AsProviderError(err); pe == nil || pe.Kind != core.ProviderBusy || pe.RetryAfter != 30*time.Second {
		t.Fatalf("busy: %v", err)
	}
	if ca.Stats().CertificatesIssued != 0 {
		t.Fatal("busy finalize must not issue")
	}

	// Fail after the effect: the certificate exists, the caller got an error,
	// and repeating the same CSR finds it.
	ca.Inject(Fault{Op: OpFinalize, Err: ca.Down(), Times: 1, AfterEffect: true})
	if _, err := ca.Finalize(ctx, order.URL, csr); kind(err) != core.ProviderDown {
		t.Fatalf("after-effect finalize: %v", err)
	}
	if ca.Stats().CertificatesIssued != 1 {
		t.Fatal("after-effect finalize must issue")
	}
	if o, err := ca.Finalize(ctx, order.URL, csr); err != nil || o.Status != core.UpstreamValid {
		t.Fatalf("repeat after lost answer: %+v, %v", o, err)
	}
	if ca.Stats().CertificatesIssued != 1 {
		t.Fatal("repeat issued a second certificate")
	}

	// Fail after the order was created: counted, visible to the test, lost
	// to the caller.
	before := ca.Stats().OrdersCreated
	ca.Inject(Fault{Op: OpNewOrder, Err: ca.Down(), Times: 1, AfterEffect: true})
	if o, err := ca.NewOrder(ctx, []string{"c.example.com"}, ""); kind(err) != core.ProviderDown || o.URL != "" {
		t.Fatalf("after-effect newOrder: %+v, %v", o, err)
	}
	if ca.Stats().OrdersCreated != before+1 {
		t.Fatal("after-effect newOrder must create the order")
	}
	if last := ca.Orders()[len(ca.Orders())-1]; last.Names[0] != "c.example.com" || last.Status != core.UpstreamPending {
		t.Fatalf("lost order = %+v", last)
	}

	// Rejected helper.
	ca.Inject(Fault{Op: OpNewOrder, Err: ca.Rejected(core.ProblemCAA, "CAA forbids"), Times: 1})
	_, err = ca.NewOrder(ctx, []string{"d.example.com"}, "")
	if pe := core.AsProviderError(err); pe == nil || pe.Kind != core.ProviderRejected || pe.Problem.Type != core.ProblemCAA {
		t.Fatalf("Rejected: %v", err)
	}

	// Slow: the call waits on the fake clock, then succeeds.
	ca.Inject(Fault{Op: OpGetOrder, Delay: time.Minute, Times: 1})
	type res struct {
		o   core.UpstreamOrder
		err error
	}
	done := make(chan res, 1)
	go func() {
		o, err := ca.GetOrder(ctx, order.URL)
		done <- res{o, err}
	}()
	if !clock.BlockUntil(1, 5*time.Second) {
		t.Fatal("slow call never started waiting")
	}
	select {
	case <-done:
		t.Fatal("slow call returned before the clock moved")
	default:
	}
	clock.Advance(time.Minute)
	if r := <-done; r.err != nil || r.o.URL != order.URL {
		t.Fatalf("slow call: %+v", r)
	}

	// Slow and cancelled: returns the context error.
	ca.Inject(Fault{Op: OpGetOrder, Delay: time.Hour, Times: 1})
	cctx, cancel := context.WithCancel(ctx)
	errc := make(chan error, 1)
	go func() {
		_, err := ca.GetOrder(cctx, order.URL)
		errc <- err
	}()
	if !clock.BlockUntil(1, 5*time.Second) {
		t.Fatal("slow call never started waiting")
	}
	cancel()
	if err := <-errc; !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled slow call: %v", err)
	}
	if _, err := ca.GetOrder(cctx, order.URL); !errors.Is(err, context.Canceled) {
		t.Fatalf("call with a dead context: %v", err)
	}
}
