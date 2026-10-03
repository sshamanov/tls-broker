//go:build pebble

package e2e

// The broker wired with the real upstream adapter against Pebble: the ACME
// proxy (new issuance, renewal with `replaces`, wildcard) and the direct
// API end to end. Route53 is still the in-memory fake, mirrored to
// challtestsrv (test/challtest) so that Pebble validates against what the
// broker published; the DNS gate still uses the fake resolver. Run with
// `make e2e-pebble`, which starts the containers (test/pebble.sh) and sets:
//
//	TLS_BROKER_PEBBLE_DIRECTORY     https://127.0.0.1:14000/dir
//	TLS_BROKER_PEBBLE_ROOT          Pebble's API TLS root (pebble.minica.pem)
//	TLS_BROKER_PEBBLE_ISSUER_ROOT   root of the certificates Pebble issues
//	TLS_BROKER_PEBBLE_CHALLTESTSRV  http://127.0.0.1:8055

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"testing"

	"tls-broker/internal/core"
	"tls-broker/internal/core/coretest"
	"tls-broker/internal/dns01"
	"tls-broker/test/challtest"
)

type pebbleWorld struct {
	b      *broker
	base   string // the managed zone, random per run
	issuer *x509.CertPool
	inter  []byte // Pebble's intermediate (DER)
}

func newPebbleBroker(t *testing.T) *pebbleWorld {
	t.Helper()
	dir := os.Getenv("TLS_BROKER_PEBBLE_DIRECTORY")
	if dir == "" {
		t.Skip("TLS_BROKER_PEBBLE_DIRECTORY not set (run make e2e-pebble)")
	}
	read := func(env string) []byte {
		b, err := os.ReadFile(os.Getenv(env))
		if err != nil {
			t.Fatalf("%s: %v", env, err)
		}
		return b
	}
	apiRoots, issuer := x509.NewCertPool(), x509.NewCertPool()
	if !apiRoots.AppendCertsFromPEM(read("TLS_BROKER_PEBBLE_ROOT")) || !issuer.AppendCertsFromPEM(read("TLS_BROKER_PEBBLE_ISSUER_ROOT")) {
		t.Fatal("no certificates in the Pebble root files")
	}
	chall := os.Getenv("TLS_BROKER_PEBBLE_CHALLTESTSRV")
	if chall == "" {
		t.Fatal("TLS_BROKER_PEBBLE_CHALLTESTSRV not set")
	}

	var rnd [4]byte
	_, _ = rand.Read(rnd[:])
	base := hex.EncodeToString(rnd[:]) + ".tlsbroker-e2e.test"
	zoneID := "ZPEBBLE" + strings.ToUpper(hex.EncodeToString(rnd[:]))

	b := &broker{t: t, clock: core.SystemClock{}, r53: dns01.NewFakeRoute53(nil), dns: coretest.NewFakeResolver(),
		dir: coretest.NewFakeDirectory(), roots: apiRoots}
	b.r53.AddZone(zoneID, base)
	b.route53 = &challtest.Route53{FakeRoute53: b.r53, Chall: challtest.NewClient(chall)}
	b.boot(func(external string) string {
		return fmt.Sprintf(`server:
  external_url: %s
  trusted_proxies: [127.0.0.1]
  real_ip_header: X-Real-IP
  shutdown_grace: 5s
zones:
  - name: %s
    hosted_zone_id: %s
route53:
  poll_interval: 200ms
upstream:
  poll_interval: 250ms
providers:
  - name: pebble
    directory_url: %s
    contact: ops@example.com
    profile: default
    caa_issuers: [pebble.letsencrypt.org]
    account_uri_honoured: false
    ari: true
    ari_exempt: true
`, external, base, zoneID, dir)
	})

	// Pebble's current intermediate, for comparing chains.
	tr := &http.Transport{TLSClientConfig: b.srv.Client().Transport.(*http.Transport).TLSClientConfig.Clone()}
	tr.TLSClientConfig.RootCAs = apiRoots
	mgmt := strings.Replace(strings.TrimSuffix(dir, "/dir"), ":14000", ":15000", 1)
	resp, err := (&http.Client{Transport: tr}).Get(mgmt + "/intermediates/0")
	if err != nil {
		t.Fatalf("Pebble intermediate: %v", err)
	}
	defer resp.Body.Close()
	pemInter, _ := io.ReadAll(resp.Body)
	blk, _ := pem.Decode(pemInter)
	if blk == nil {
		t.Fatalf("Pebble intermediate: %d %s", resp.StatusCode, pemInter)
	}
	return &pebbleWorld{b: b, base: base, issuer: issuer, inter: blk.Bytes}
}

// verify checks a chain: leaf for name, issued by Pebble's current
// intermediate, verifying to Pebble's root, and without the root.
func (w *pebbleWorld) verify(chainPEM []byte, name string) *x509.Certificate {
	t := w.b.t
	t.Helper()
	certs, err := coretest.ParseChain(chainPEM)
	if err != nil {
		t.Fatal(err)
	}
	if len(certs) != 2 || !bytes.Equal(certs[1].Raw, w.inter) {
		t.Fatalf("chain of %d certificates; intermediate is Pebble's: %v", len(certs), len(certs) > 1 && bytes.Equal(certs[1].Raw, w.inter))
	}
	inters := x509.NewCertPool()
	inters.AddCert(certs[1])
	if _, err := certs[0].Verify(x509.VerifyOptions{Roots: w.issuer, Intermediates: inters, DNSName: name}); err != nil {
		t.Fatalf("chain does not verify against Pebble's root: %v", err)
	}
	return certs[0]
}

func TestPebble(t *testing.T) {
	w := newPebbleBroker(t)
	b := w.b
	www, api, apex := "www."+w.base, "api."+w.base, w.base
	m := b.machine("10.1.0.1", www, api, apex)
	c := m.acme()

	t.Run("new issuance", func(t *testing.T) {
		is := c.issue("", www)
		w.verify(is.chain, www)
		multi := c.issue("", api, www)
		w.verify(multi.chain, api)
		if o := b.order(multi.orderID); o.Provider != "pebble" || o.UpstreamOrderURL == "" || o.Status != core.OrderValid {
			t.Fatalf("broker order %+v", o)
		}
	})

	t.Run("renewal with replaces", func(t *testing.T) {
		first := c.issue("", www)
		ri, err := c.core.Certificates.GetRenewalInfo(context.Background(), first.certID)
		if err != nil || ri.SuggestedWindow.Start.IsZero() {
			t.Fatalf("renewalInfo from Pebble: %+v %v", ri, err)
		}
		r := c.issue(first.certID, www)
		w.verify(r.chain, www)
		o := b.order(r.orderID)
		if r.created.Replaces != first.certID || o.UpstreamReplaces != first.certID {
			t.Fatalf("replaces: echoed %q, upstream %q", r.created.Replaces, o.UpstreamReplaces)
		}
		nc, pc := b.certByARI(r.certID), b.certByARI(first.certID)
		if nc.ReplacesID != pc.ID || pc.ReplacedByID != nc.ID || nc.AccountURL != pc.AccountURL {
			t.Fatalf("renewal %+v of %+v", nc, pc)
		}
		// Without replaces from the client the broker infers it.
		r2 := c.issue("", www)
		if o := b.order(r2.orderID); o.UpstreamReplaces != r.certID {
			t.Fatalf("inferred replaces %q, want %q", o.UpstreamReplaces, r.certID)
		}
	})

	t.Run("wildcard", func(t *testing.T) {
		wm := b.machine("10.1.0.2", apex)
		_, err := wm.acme().newOrder("", "*."+apex, apex)
		deniedACME(t, err, core.ReasonWildcardGrantRequired)
		b.grant("10.1.0.2", true)
		is := wm.acme().issue("", "*."+apex, apex)
		w.verify(is.chain, "x."+apex)
		if v := b.r53.TXT("_acme-challenge." + apex); len(v) != 0 {
			t.Fatalf("values left behind: %v", v)
		}
	})

	t.Run("direct", func(t *testing.T) {
		dm := b.machine("10.1.0.3", "dev."+apex)
		code, _, dc, body := dm.fetch("dev." + apex)
		if code != http.StatusOK {
			t.Fatalf("direct miss: %d %s", code, body)
		}
		w.verify(dc.chain, "dev."+apex)
		code, _, hit, _ := dm.fetch("dev." + apex)
		if code != http.StatusOK || hit.etag != dc.etag {
			t.Fatalf("direct hit: %d", code)
		}
	})

	b.checkInvariants(0)
}
