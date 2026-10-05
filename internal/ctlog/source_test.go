package ctlog

import (
	"context"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"errors"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"tls-broker/internal/core/coretest"
)

// testDER is a self-signed certificate with serial 0x0abc01.
func testDER(t *testing.T) []byte {
	t.Helper()
	key := coretest.GenKey()
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(0x0abc01), Subject: pkix.Name{CommonName: "pass.example.com"},
		DNSNames: []string{"pass.example.com"}, NotBefore: time.Unix(0, 0), NotAfter: time.Unix(1e9, 0)}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

func fixture(t *testing.T) []byte {
	t.Helper()
	b, err := os.ReadFile("testdata/certspotter-page.json")
	if err != nil {
		t.Fatal(err)
	}
	return []byte(strings.Replace(string(b), "__CERT_DER__", base64.StdEncoding.EncodeToString(testDER(t)), 1))
}

// The fixture is a real Cert Spotter page (names replaced by example.com).
func TestParseCertSpotter(t *testing.T) {
	list, err := ParseCertSpotter(fixture(t))
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 4 {
		t.Fatalf("got %d issuances", len(list))
	}
	first := list[0]
	if first.ID != "15766129210" || first.Key() != "pass.example.com" || first.Issuer != "Let's Encrypt" ||
		first.IssuerDN != "C=US, O=Let's Encrypt, CN=YR2" || len(first.IssuerCAA) != 1 || first.IssuerCAA[0] != "letsencrypt.org" ||
		!first.NotBefore.Equal(time.Date(2026, 7, 9, 10, 19, 25, 0, time.UTC)) || first.Revoked || first.TBSSHA256 == "" {
		t.Fatalf("first = %+v", first)
	}
	if !list[1].Revoked {
		t.Fatal("revoked flag lost")
	}
	if list[2].Serial != "abc01" {
		t.Fatalf("serial from cert_der = %q", list[2].Serial)
	}
	if list[0].Serial != "" {
		t.Fatal("no cert_der must mean no serial")
	}
	if got := list[3].Key(); got != "minio.example.com,qa.example.com" {
		t.Fatalf("names not normalized: %q", got)
	}
	if got := list[2].Key(); got != "*.dev.example.com,*.example.com,example.com" {
		t.Fatalf("wildcards: %q", got)
	}
	if _, err := ParseCertSpotter([]byte(`[{"id":"1"}]`)); err == nil {
		t.Fatal("issuance without tbs_sha256 accepted")
	}
	if _, err := ParseCertSpotter([]byte(`{"code":"x"}`)); err == nil {
		t.Fatal("object accepted as page")
	}
}

func TestCertSpotterHTTP(t *testing.T) {
	page := fixture(t)
	var queries []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		queries = append(queries, r.URL.RawQuery)
		switch {
		case q.Get("domain") == "limited.example":
			w.Header().Set("Retry-After", "3600")
			w.WriteHeader(http.StatusTooManyRequests)
			_, _ = w.Write([]byte(`{"code":"rate_limited","message":"Client request rate has exceeded what your subscription allows"}`))
		case q.Get("domain") == "broken.example":
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = w.Write([]byte(`{"code":"internal_error","message":"boom"}`))
		case q.Get("after") == "":
			_, _ = w.Write(page)
		default:
			_, _ = w.Write([]byte(`[]`))
		}
	}))
	defer srv.Close()
	cs := &CertSpotter{Endpoint: srv.URL, UserAgent: "test"}
	ctx := context.Background()

	list, err := cs.List(ctx, "example.com", "")
	if err != nil || len(list) != 4 {
		t.Fatalf("first page: %d %v", len(list), err)
	}
	if q := queries[0]; !strings.Contains(q, "domain=example.com") || !strings.Contains(q, "include_subdomains=true") ||
		!strings.Contains(q, "match_wildcards=true") || !strings.Contains(q, "expand=issuer.caa_domains") ||
		!strings.Contains(q, "expand=cert_der") || !strings.Contains(q, "expand=dns_names") || strings.Contains(q, "after=") {
		t.Fatalf("query %q", q)
	}
	list, err = cs.List(ctx, "example.com", list[3].ID)
	if err != nil || len(list) != 0 || !strings.Contains(queries[1], "after=17597250121") {
		t.Fatalf("next page: %v %v %q", list, err, queries[1])
	}

	_, err = cs.List(ctx, "limited.example", "")
	var rl *RateLimitError
	if !errors.As(err, &rl) || rl.RetryAfter != time.Hour || !strings.Contains(rl.Message, "exceeded") {
		t.Fatalf("rate limit: %v", err)
	}
	_, err = cs.List(ctx, "broken.example", "")
	if err == nil || errors.As(err, &rl) || !strings.Contains(err.Error(), "boom") {
		t.Fatalf("server error: %v", err)
	}
}

func TestFakeSourcePages(t *testing.T) {
	f := NewFakeSource(2)
	f.Add(iss("a", "x.example.com"), iss("b", "*.example.com"), iss("c", "other.test"), iss("d", "example.com"))
	ctx := context.Background()
	p1, _ := f.List(ctx, "example.com", "")
	p2, _ := f.List(ctx, "example.com", p1[len(p1)-1].ID)
	p3, _ := f.List(ctx, "example.com", p2[len(p2)-1].ID)
	if len(p1) != 2 || len(p2) != 1 || p2[0].TBSSHA256 != "d" || len(p3) != 0 {
		t.Fatalf("pages %v %v %v", p1, p2, p3)
	}
}
