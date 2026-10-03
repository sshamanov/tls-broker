package e2e

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/x509"
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"tls-broker/internal/core"
	"tls-broker/internal/core/coretest"
)

// directCert is a parsed /cert/ response.
type directCert struct {
	etag  string
	leaf  *x509.Certificate
	chain []byte
	key   []byte
}

// fetch GETs /cert/<p> and parses the tar of a 200.
func (m *machine) fetch(p string, hdr ...string) (int, http.Header, *directCert, []byte) {
	t := m.b.t
	t.Helper()
	code, h, body := m.get("/cert/"+p, hdr...)
	if code != http.StatusOK {
		return code, h, nil, body
	}
	dc := &directCert{etag: h.Get("ETag")}
	tr := tar.NewReader(bytes.NewReader(body))
	for {
		hd, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatalf("tar: %v", err)
		}
		b, _ := io.ReadAll(tr)
		switch hd.Name {
		case "privkey.pem":
			dc.key = b
		case "fullchain.pem":
			dc.chain = b
		default:
			t.Fatalf("unexpected tar member %q", hd.Name)
		}
	}
	chain, err := coretest.ParseChain(dc.chain)
	if err != nil || len(dc.key) == 0 || dc.etag == "" {
		t.Fatalf("direct response: chain %v, key %d bytes, etag %q", err, len(dc.key), dc.etag)
	}
	dc.leaf = chain[0]
	return code, h, dc, body
}

// waitARIChecked waits until the background renewal-information check a
// fetch started has stored its schedule (so the next step of a test does not
// race with it).
func (b *broker) waitARIChecked(id string) {
	b.t.Helper()
	eventually(b.t, "renewal information check of "+id, func() bool {
		return b.directEntry(id).NextARICheckAt.After(b.clock.Now())
	})
}

func (b *broker) directEntry(id string) *core.DirectEntry {
	b.t.Helper()
	e, err := b.app().Store().Direct().Get(context.Background(), id)
	if err != nil {
		b.t.Fatalf("direct entry %s: %v", id, err)
	}
	return e
}

// The direct cache: a miss issues synchronously; hits do no upstream work
// (also with If-None-Match → 304, and while the CA is down); nothing renews
// without a fetch; a fetch with renewal due serves the current certificate
// and renews in the background; inside the emergency window with the primary
// down the renewal moves to the fallback; an expired certificate is never
// served.
func testDirectCache(t *testing.T) {
	b := newFakeBroker(t)
	m := b.machine("10.0.0.60", "dev.example.com")

	// Miss.
	code, _, first, body := m.fetch("dev.example.com")
	if code != http.StatusOK {
		t.Fatalf("miss: %d %s", code, body)
	}
	if _, err := b.le.VerifyChain(first.chain, "dev.example.com"); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(first.key), "BEGIN RSA PRIVATE KEY") {
		t.Fatal("key is not PKCS#1 RSA")
	}
	if s := b.le.Stats(); s.OrdersCreated != 1 || s.CertificatesIssued != 1 {
		t.Fatalf("after miss: %+v", s)
	}
	if o, err := b.app().Store().Orders().List(context.Background(), core.OrderFilter{Mode: core.ModeDirect}); err != nil || len(o) != 1 || o[0].Class != core.ClassDirectMiss {
		t.Fatalf("direct orders %+v %v", o, err)
	}

	// Hits: same generation, 304 with the ETag, served through an outage.
	if code, _, hit, _ := m.fetch("dev.example.com"); code != http.StatusOK || hit.etag != first.etag {
		t.Fatalf("hit: %d", code)
	}
	b.waitARIChecked("dev.example.com")
	if code, _, _ := m.get("/cert/dev.example.com", "If-None-Match", first.etag); code != http.StatusNotModified {
		t.Fatalf("conditional hit: %d", code)
	}
	b.le.Inject(coretest.Fault{Op: coretest.OpAny, Err: b.le.Down()})
	b.advance(day)
	if code, _, hit, body := m.fetch("dev.example.com"); code != http.StatusOK || hit.etag != first.etag {
		t.Fatalf("hit during outage: %d %s", code, body)
	}
	b.waitARIChecked("dev.example.com")
	b.le.ClearFaults()
	if s := b.le.Stats(); s.OrdersCreated != 1 {
		t.Fatalf("hits caused upstream orders: %+v", s)
	}

	// Renewal is request-driven: past the ARI window nothing happens until
	// the device fetches again.
	b.advance(64 * day) // day 65; the window was days 60-62
	b.housekeep()
	time.Sleep(50 * time.Millisecond)
	if s := b.le.Stats(); s.OrdersCreated != 1 {
		t.Fatalf("renewed without a fetch: %+v", s)
	}
	code, _, cur, _ := m.fetch("dev.example.com")
	if code != http.StatusOK || cur.etag != first.etag {
		t.Fatalf("fetch with renewal due must serve the current certificate at once: %d", code)
	}
	eventually(t, "background renewal", func() bool { return b.directEntry("dev.example.com").Generation == 2 })
	_, _, renewed, _ := m.fetch("dev.example.com")
	b.waitARIChecked("dev.example.com")
	if renewed.etag == first.etag || !renewed.leaf.NotAfter.After(first.leaf.NotAfter) {
		t.Fatalf("not renewed: %s", renewed.leaf.NotAfter)
	}
	if string(renewed.key) != string(first.key) {
		t.Fatal("renewal changed the key")
	}
	if s := b.le.Stats(); s.OrdersCreated != 2 || s.CertificatesIssued != 2 {
		t.Fatalf("after renewal: %+v", s)
	}

	// Emergency: three days before expiry, the primary is down; the fetch is
	// served and the renewal moves to google.
	b.fc.Set(renewed.leaf.NotAfter.Add(-3 * day))
	b.le.Inject(coretest.Fault{Op: coretest.OpAny, Err: b.le.Down()})
	code, _, cur, body = m.fetch("dev.example.com")
	if code != http.StatusOK || cur.etag != renewed.etag {
		t.Fatalf("emergency fetch: %d %s", code, body)
	}
	eventually(t, "emergency renewal at the fallback", func() bool { return b.directEntry("dev.example.com").Provider == "google" })
	_, _, em, _ := m.fetch("dev.example.com")
	if _, err := b.goog.VerifyChain(em.chain, "dev.example.com"); err != nil {
		t.Fatalf("emergency certificate: %v", err)
	}

	// Expired and nothing can issue: 503, never the expired certificate.
	b.goog.Inject(coretest.Fault{Op: coretest.OpAny, Err: b.goog.Down()})
	b.fc.Set(em.leaf.NotAfter.Add(time.Hour))
	code, hdr, _, body := m.fetch("dev.example.com")
	if code != http.StatusServiceUnavailable || hdr.Get("Retry-After") == "" || bytes.Contains(body, []byte("CERTIFICATE")) {
		t.Fatalf("expired: %d %q %.200s", code, hdr.Get("Retry-After"), body)
	}
	if evs := b.auditEvents(core.AuditDirectFetch); len(evs) < 8 {
		t.Fatalf("direct_fetch audit events: %d", len(evs))
	}
	b.checkInvariants(0)
}

// Concurrent misses for one identifier share one issuance job: one upstream
// order, one certificate, every client gets it.
func testDirectCollapse(t *testing.T) {
	b := newFakeBroker(t)
	m := b.machine("10.0.0.61", "dup.example.com")
	b.le.Inject(coretest.Fault{Op: coretest.OpWaitReady, Delay: time.Minute, Times: 1})

	const n = 8
	type res struct {
		code int
		etag string
	}
	results := make(chan res, n)
	var wg sync.WaitGroup
	for range n {
		wg.Add(1)
		go func() {
			defer wg.Done()
			code, hdr, _ := m.get("/cert/dup.example.com")
			results <- res{code, hdr.Get("ETag")}
		}()
	}
	// The first issuance is stuck in the slow CA; give the other requests
	// time to arrive and join it, and check there is still one order.
	eventually(t, "issuance in progress", func() bool { return b.le.Stats().Calls[coretest.OpWaitReady] == 1 })
	time.Sleep(100 * time.Millisecond)
	if active, err := b.app().Store().Orders().ListActive(context.Background()); err != nil || len(active) != 1 {
		t.Fatalf("active orders while %d requests wait: %d %v", n, len(active), err)
	}
	b.pump(time.Second, wg.Wait)
	close(results)
	etag := ""
	for r := range results {
		if r.code != http.StatusOK || etag != "" && r.etag != etag {
			t.Fatalf("result %+v (etag %q)", r, etag)
		}
		etag = r.etag
	}
	if s := b.le.Stats(); s.OrdersCreated != 1 || s.CertificatesIssued != 1 {
		t.Fatalf("CA stats %+v", s)
	}
	if evs := b.auditEvents(core.AuditIssue); len(evs) != 1 {
		t.Fatalf("issue events: %d", len(evs))
	}
	b.checkInvariants(0)
}
