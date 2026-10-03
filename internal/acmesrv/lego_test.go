package acmesrv

import (
	"context"
	"crypto"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/go-acme/lego/v5/acme"
	"github.com/go-acme/lego/v5/acme/api"

	"tls-broker/internal/core"
	"tls-broker/internal/core/coretest"
)

func (e *env) lego(key crypto.Signer, kid string) *api.Core {
	e.t.Helper()
	c, err := api.New(e.httpClient(), "acmesrv-test", e.url(pathDirectory), kid, key)
	if err != nil {
		e.t.Fatal(err)
	}
	return c
}

func legoRegister(t *testing.T, c *api.Core) acme.ExtendedAccount {
	t.Helper()
	acct, err := c.Accounts.New(context.Background(), acme.Account{
		Contact: []string{"mailto:ops@example.com"}, TermsOfServiceAgreed: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	return acct
}

// TestLegoFullFlow drives account, newOrder (wildcard + plain), authz,
// challenge, finalize, certificate download, ARI, keyChange and
// deactivation through lego's low-level client.
func TestLegoFullFlow(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	key := coretest.GenKey()
	c := e.lego(key, "")

	acct := legoRegister(t, c)
	if acct.Status != "valid" || !strings.HasPrefix(acct.Location, e.url(pathAccount)) {
		t.Fatalf("account %+v", acct)
	}
	// The same key again finds the same account.
	again, err := e.lego(key, "").Accounts.New(ctx, acme.Account{TermsOfServiceAgreed: true})
	if err != nil || again.Location != acct.Location {
		t.Fatalf("second newAccount: %v %q", err, again.Location)
	}
	got, err := c.Accounts.Get(ctx, acct.Location)
	if err != nil || len(got.Contact) != 1 || got.Orders == "" {
		t.Fatalf("account get: %+v %v", got, err)
	}
	upd, err := c.Accounts.Update(ctx, acct.Location, acme.Account{Contact: []string{"mailto:new@example.com"}})
	if err != nil || upd.Contact[0] != "mailto:new@example.com" {
		t.Fatalf("account update: %+v %v", upd, err)
	}

	domains := []string{"www.example.com", "*.example.com"}
	order, err := c.Orders.New(ctx, domains, &api.OrderOptions{Profile: "tlsserver"})
	if err != nil {
		t.Fatal(err)
	}
	if order.Status != "ready" || order.Location == "" || order.Finalize == "" || len(order.Authorizations) != 2 || order.Expires == "" {
		t.Fatalf("order %+v", order)
	}
	adm := e.iss.Admits()
	if len(adm) != 1 || adm[0].Names.Key() != "*.example.com,www.example.com" || adm[0].SourceIP.String() != "127.0.0.1" ||
		!adm[0].Decision.Allowed {
		t.Fatalf("admit requests %+v", adm)
	}
	wildcards := 0
	for _, u := range order.Authorizations {
		az, err := c.Authorizations.Get(ctx, u)
		if err != nil {
			t.Fatal(err)
		}
		if az.Status != "valid" || az.Identifier.Value != "example.com" && az.Identifier.Value != "www.example.com" ||
			len(az.Challenges) != 1 || az.Challenges[0].Type != "dns-01" || az.Challenges[0].Status != "valid" ||
			az.Challenges[0].Token == "" || az.Challenges[0].Validated.IsZero() || az.Expires.IsZero() {
			t.Fatalf("authorization %+v", az)
		}
		if az.Wildcard {
			wildcards++
			if az.Identifier.Value != "example.com" {
				t.Fatalf("wildcard identifier %q", az.Identifier.Value)
			}
		}
		ch, err := c.Challenges.New(ctx, az.Challenges[0].URL)
		if err != nil || ch.Status != "valid" || ch.AuthorizationURL != u {
			t.Fatalf("challenge response: %+v %v", ch, err)
		}
	}
	if wildcards != 1 {
		t.Fatalf("wildcard authorizations: %d", wildcards)
	}

	csrKey := coretest.GenKey()
	fin, err := c.Orders.UpdateForCSR(ctx, order.Finalize, coretest.MakeCSR(csrKey, domains...))
	if err != nil {
		t.Fatal(err)
	}
	if fin.Status != "valid" || fin.Certificate == "" {
		t.Fatalf("finalized order %+v", fin)
	}
	polled, err := c.Orders.Get(ctx, order.Location)
	if err != nil || polled.Status != "valid" || polled.Certificate != fin.Certificate {
		t.Fatalf("poll: %+v %v", polled, err)
	}
	raw, err := c.Certificates.Get(ctx, fin.Certificate, true)
	if err != nil {
		t.Fatal(err)
	}
	chain, err := coretest.ParseChain(raw.Cert)
	if err != nil || len(chain) != 2 || chain[0].DNSNames[0] != "www.example.com" {
		t.Fatalf("chain: %v %d", err, len(chain))
	}

	// ARI for the issued certificate.
	certID, err := api.MakeARICertID(chain[0])
	if err != nil {
		t.Fatal(err)
	}
	e.iss.mu.Lock()
	e.iss.riRetryAfter = 2 * time.Hour
	e.iss.mu.Unlock()
	ri, err := c.Certificates.GetRenewalInfo(ctx, certID)
	if err != nil {
		t.Fatal(err)
	}
	if ri.RetryAfter != 2*time.Hour || ri.SuggestedWindow.Start.IsZero() || !ri.SuggestedWindow.End.After(ri.SuggestedWindow.Start) ||
		ri.ExplanationURL != "https://primary.test/ari-explained" {
		t.Fatalf("renewal info %+v", ri)
	}

	// A renewal naming the certificate in replaces is echoed.
	renewal, err := c.Orders.New(ctx, domains, &api.OrderOptions{ReplacesCertID: certID})
	if err != nil {
		t.Fatal(err)
	}
	if renewal.Replaces != certID || e.iss.Admits()[1].Replaces != certID {
		t.Fatalf("renewal replaces %q, admit %+v", renewal.Replaces, e.iss.Admits()[1])
	}
	// An unknown replaces is passed on but not echoed.
	other, err := c.Orders.New(ctx, []string{"other.example.org"}, &api.OrderOptions{ReplacesCertID: "AAAA.BBBB"})
	if err != nil || other.Replaces != "" {
		t.Fatalf("unknown replaces: %+v %v", other, err)
	}

	// keyChange: afterwards the new key works and the old one does not.
	newKey := coretest.GenKey()
	if err := c.Accounts.KeyChange(ctx, newKey); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Orders.Get(ctx, order.Location); err != nil {
		t.Fatalf("new key after keyChange: %v", err)
	}
	old := e.lego(key, acct.Location)
	if _, err := old.Orders.Get(ctx, order.Location); err == nil {
		t.Fatal("old key still accepted after keyChange")
	}
	if _, err := e.lego(newKey, "").Accounts.New(ctx, acme.Account{OnlyReturnExisting: true}); err != nil {
		t.Fatalf("lookup by new key: %v", err)
	}

	// Deactivation ends the account.
	if err := c.Accounts.Deactivate(ctx, acct.Location); err != nil {
		t.Fatal(err)
	}
	_, err = c.Orders.New(ctx, []string{"x.example.com"}, nil)
	var pd *acme.ProblemDetails
	if !errors.As(err, &pd) || pd.Type != core.ProblemUnauthorized {
		t.Fatalf("deactivated account: %v", err)
	}
}

// TestLegoProcessingThenValid: finalize answers processing with
// Retry-After; polling the order shows processing until the certificate is
// issued, then valid.
func TestLegoProcessingThenValid(t *testing.T) {
	e := newEnv(t)
	e.iss.setFinalizeValid(false)
	ctx := context.Background()
	c := e.lego(coretest.GenKey(), "")
	legoRegister(t, c)
	order, err := c.Orders.New(ctx, []string{"app.example.com"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	csr := coretest.MakeCSR(coretest.GenKey(), "app.example.com")
	fin, err := c.Orders.UpdateForCSR(ctx, order.Finalize, csr)
	if err != nil || fin.Status != "processing" || fin.Certificate != "" {
		t.Fatalf("finalize: %+v %v", fin, err)
	}
	// The same CSR again is idempotent.
	if again, err := c.Orders.UpdateForCSR(ctx, order.Finalize, csr); err != nil || again.Status != "processing" {
		t.Fatalf("finalize retry: %+v %v", again, err)
	}
	if n := len(e.iss.Finalizes()); n != 2 {
		t.Fatalf("issuer finalize calls %d", n)
	}

	id := strings.TrimPrefix(order.Location, e.url(pathOrder))
	if err := e.iss.complete(ctx, id); err != nil {
		t.Fatal(err)
	}
	polled, err := c.Orders.Get(ctx, order.Location)
	if err != nil || polled.Status != "valid" || polled.Certificate == "" {
		t.Fatalf("poll: %+v %v", polled, err)
	}
}

// TestProcessingRetryAfter checks the Retry-After header on finalize and on
// order polls while the order is processing.
func TestProcessingRetryAfter(t *testing.T) {
	e := newEnv(t)
	e.iss.setFinalizeValid(false)
	c := e.newRaw(coretest.GenKey()).register()
	o, loc := c.newOrder("app.example.com")
	r := c.post(o.Finalize, csrPayload(coretest.MakeCSR(coretest.GenKey(), "app.example.com")))
	if r.StatusCode != http.StatusOK || r.Header.Get("Retry-After") != "3" || !strings.Contains(string(r.body), `"status":"processing"`) {
		t.Fatalf("finalize: %d %q %s", r.StatusCode, r.Header.Get("Retry-After"), r.body)
	}
	r = c.post(loc, nil)
	if r.StatusCode != http.StatusOK || r.Header.Get("Retry-After") != "3" {
		t.Fatalf("poll: %d %q %s", r.StatusCode, r.Header.Get("Retry-After"), r.body)
	}
}

// TestLegoRateLimited: an admission refusal reaches the client as 429
// rateLimited with Retry-After, and is audited as a rate_limit event.
func TestLegoRateLimited(t *testing.T) {
	e := newEnv(t)
	c := e.lego(coretest.GenKey(), "")
	legoRegister(t, c)
	e.iss.setAdmitErr(&core.AdmissionError{Kind: core.AdmissionRateLimited, Provider: "primary",
		RetryAfter: 90 * time.Minute, Reason: "certificates per registered domain example.com"})
	_, err := c.Orders.New(context.Background(), []string{"www.example.com"}, nil)
	var rl *acme.RateLimitedError
	if !errors.As(err, &rl) || rl.RetryAfter != 90*time.Minute || !strings.Contains(rl.Detail, "example.com") {
		t.Fatalf("rate limited: %#v", err)
	}
	evs := e.aud.OfType(core.AuditRateLimit)
	if len(evs) != 1 || evs[0].Reason != core.ReasonRateLimited || evs[0].Provider != "primary" || evs[0].Mode != core.ModeACME {
		t.Fatalf("audit %+v", evs)
	}
}
