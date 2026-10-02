//go:build pebble

package upstream

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	"tls-broker/internal/core"
	"tls-broker/internal/core/coretest"
)

// Environment of the Pebble test (see docs/providers.md, "Testing against
// Pebble"). The test is skipped when TLS_BROKER_PEBBLE_DIRECTORY is unset.
const (
	envPebbleDirectory = "TLS_BROKER_PEBBLE_DIRECTORY"    // https://127.0.0.1:14000/dir
	envPebbleRoot      = "TLS_BROKER_PEBBLE_ROOT"         // pebble.minica.pem (API TLS root)
	envChallTestSrv    = "TLS_BROKER_PEBBLE_CHALLTESTSRV" // http://127.0.0.1:8055
)

func pebbleEnv(t *testing.T) (dir, root, chall string) {
	dir, root, chall = os.Getenv(envPebbleDirectory), os.Getenv(envPebbleRoot), os.Getenv(envChallTestSrv)
	if dir == "" {
		t.Skipf("%s not set", envPebbleDirectory)
	}
	if root == "" || chall == "" {
		t.Fatalf("%s needs %s and %s", envPebbleDirectory, envPebbleRoot, envChallTestSrv)
	}
	return dir, root, chall
}

func challSet(t *testing.T, ctx context.Context, base, op, host, value string) {
	t.Helper()
	body, _ := json.Marshal(map[string]string{"host": host + ".", "value": value})
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, base+"/"+op, bytes.NewReader(body))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("challtestsrv %s: HTTP %d", op, resp.StatusCode)
	}
}

func TestPebbleFullFlow(t *testing.T) {
	dir, rootFile, chall := pebbleEnv(t)
	pemRoot, err := os.ReadFile(rootFile)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(pemRoot) {
		t.Fatalf("no certificate in %s", rootFile)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	secrets := coretest.NewFakeSecrets()
	up := core.DefaultConfig().Upstream
	up.PollInterval = 500 * time.Millisecond
	cfg := core.ProviderConfig{Name: "pebble", DirectoryURL: dir, Contact: "ops@example.com", ARI: true, ARIExempt: true}
	newProvider := func(mod ...func(*core.ProviderConfig)) *ACMEProvider {
		c := cfg
		for _, m := range mod {
			m(&c)
		}
		p, err := NewACMEProvider(c, up, Options{Secrets: secrets, RootCAs: roots})
		if err != nil {
			t.Fatal(err)
		}
		return p
	}
	p := newProvider()

	acct, err := p.AccountURL(ctx)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("account %s", acct)
	if again, err := newProvider().AccountURL(ctx); err != nil || again != acct {
		t.Fatalf("second instance account = %q, %v", again, err)
	}

	var rnd [4]byte
	_, _ = rand.Read(rnd[:])
	base := hex.EncodeToString(rnd[:]) + ".tlsbroker-pebble.test"
	orderNames := []string{"*." + base, base}

	issue := func(p *ACMEProvider, replaces string) (*x509.Certificate, string) {
		t.Helper()
		o, err := p.NewOrder(ctx, orderNames, replaces)
		if err != nil {
			t.Fatalf("NewOrder(replaces=%q): %v", replaces, err)
		}
		chs, err := p.DNSChallenges(ctx, o)
		if err != nil {
			t.Fatal(err)
		}
		if len(chs) == 0 {
			t.Logf("authorizations reused, nothing to prove")
		}
		for _, ch := range chs {
			if ch.RecordName != "_acme-challenge."+base {
				t.Fatalf("record name %q", ch.RecordName)
			}
			challSet(t, ctx, chall, "set-txt", ch.RecordName, ch.Value)
		}
		defer func() {
			for _, ch := range chs {
				challSet(t, ctx, chall, "clear-txt", ch.RecordName, "")
			}
		}()
		for _, ch := range chs {
			if err := p.Accept(ctx, ch); err != nil {
				t.Fatal(err)
			}
		}
		if _, err := p.WaitReady(ctx, o.URL); err != nil {
			t.Fatal(err)
		}
		key := coretest.GenKey()
		csr := coretest.MakeCSR(key, base, "*."+base)
		fin, err := p.Finalize(ctx, o.URL, csr)
		if err != nil {
			t.Fatal(err)
		}
		if fin.Status != core.UpstreamProcessing && fin.Status != core.UpstreamValid {
			t.Fatalf("finalize status %s", fin.Status)
		}
		if _, err := p.Finalize(ctx, o.URL, csr); err != nil {
			t.Fatalf("repeated Finalize: %v", err)
		}
		chain, err := p.WaitCertificate(ctx, o.URL)
		if err != nil {
			t.Fatal(err)
		}
		certs, err := coretest.ParseChain(chain)
		if err != nil {
			t.Fatal(err)
		}
		if len(certs) < 2 {
			t.Fatalf("chain has %d certificates, want leaf + intermediates", len(certs))
		}
		for _, c := range certs[1:] {
			if bytes.Equal(c.RawIssuer, c.RawSubject) {
				t.Fatal("chain contains a root")
			}
		}
		if !slices.Contains(certs[0].DNSNames, "*."+base) || !slices.Contains(certs[0].DNSNames, base) {
			t.Fatalf("leaf names %v", certs[0].DNSNames)
		}
		id, err := core.ARICertID(certs[0])
		if err != nil {
			t.Fatal(err)
		}
		return certs[0], id
	}

	_, id := issue(p, "")
	ri, err := p.RenewalInfo(ctx, id)
	if err != nil {
		t.Fatalf("RenewalInfo: %v", err)
	}
	if !ri.WindowEnd.After(ri.WindowStart) {
		t.Fatalf("renewal info %+v", ri)
	}
	t.Logf("renewal window %s .. %s, retry after %s", ri.WindowStart, ri.WindowEnd, ri.RetryAfter)

	// A replacement order, then a second one for the same predecessor.
	_, _ = issue(p, id)
	_, err = p.NewOrder(ctx, orderNames, id)
	switch pe := core.AsProviderError(err); {
	case pe != nil && pe.Kind == core.ProviderAlreadyReplaced:
		t.Logf("second replaces: already_replaced as expected")
	case err == nil:
		t.Fatalf("second replaces order for %s was accepted", id)
	default:
		t.Fatalf("second replaces: %v", err)
	}

	// The configured profile reaches the CA: Pebble's "default" issues
	// 90-day and "shortlived" six-day certificates. (Without a profile
	// Pebble may pick either, so both are requested explicitly.)
	for profile, long := range map[string]bool{"default": true, "shortlived": false} {
		leaf, _ := issue(newProvider(func(c *core.ProviderConfig) { c.Profile = profile }), "")
		if life := leaf.NotAfter.Sub(leaf.NotBefore); (life > 80*24*time.Hour) != long {
			t.Fatalf("profile %s: lifetime %s", profile, life)
		}
	}

	// Errors from a real CA: an unknown order and an unknown certificate.
	_, err = p.GetOrder(ctx, strings.TrimSuffix(dir, "/dir")+"/my-order/does-not-exist")
	if pe := core.AsProviderError(err); pe == nil || pe.Kind != core.ProviderRejected {
		t.Fatalf("unknown order: %v", err)
	}
	_, err = p.RenewalInfo(ctx, "AAAA.AAAA")
	if pe := core.AsProviderError(err); pe == nil || pe.Kind != core.ProviderRejected {
		t.Fatalf("unknown certificate renewal info: %v", err)
	}
	t.Logf("pebble flow complete for %s", base)
}
