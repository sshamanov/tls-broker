package main

import (
	"context"
	"encoding/base64"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/miekg/dns"

	"tls-broker/internal/core"
	"tls-broker/internal/doh"
)

func newServer(t *testing.T, upstream string, lines ...string) *httptest.Server {
	t.Helper()
	table := records{}
	for _, l := range lines {
		if err := table.add(l, 60); err != nil {
			t.Fatal(err)
		}
	}
	mux := http.NewServeMux()
	mux.Handle("/dns-query", &server{table: table, upstream: upstream, client: http.DefaultClient,
		log: slog.New(slog.NewTextHandler(io.Discard, nil))})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

func TestAgainstDoHResolver(t *testing.T) {
	ctx := context.Background()
	srv := newServer(t, "",
		"text2.example.com A 192.0.2.10",
		"Alpha.example.com\tA   10.0.0.9",
		"Multi.Example.COM. A 10.0.0.1",
		"multi.example.com A 10.0.0.2",
		"www.example.com CNAME alias.example.com",
		"alias.example.com CNAME text2.example.com",
		"_acme-challenge.text2.example.com TXT \"tok en\"",
		`example.com CAA 0 issue "letsencrypt.org; accounturi=https://acme.example/acct/1"`,
		"dangling.example.com CNAME elsewhere.example",
	)
	r := doh.New(nil, doh.WithEndpoints(srv.URL+"/dns-query"))

	addrs, err := r.LookupA(ctx, "www.example.com")
	if err != nil || !slices.Equal(addrs, []netip.Addr{netip.MustParseAddr("192.0.2.10")}) {
		t.Fatalf("A via CNAME chain: %v %v", addrs, err)
	}
	if addrs, _ := r.LookupA(ctx, "alpha.example.com"); len(addrs) != 1 || addrs[0].String() != "10.0.0.9" {
		t.Fatalf("type letter inside the name: %v", addrs)
	}
	if addrs, _ := r.LookupA(ctx, "multi.example.com"); len(addrs) != 2 {
		t.Fatalf("names are case-insensitive, records accumulate: %v", addrs)
	}
	if txt, err := r.LookupTXT(ctx, "_acme-challenge.text2.example.com"); err != nil || !slices.Equal(txt, []string{"tok en"}) {
		t.Fatalf("TXT: %q %v", txt, err)
	}
	caa, err := r.LookupCAA(ctx, "example.com")
	if err != nil || len(caa) != 1 || caa[0] != (core.CAA{Tag: "issue", Value: "letsencrypt.org; accounturi=https://acme.example/acct/1"}) {
		t.Fatalf("CAA: %+v %v", caa, err)
	}
	// Unknown names and NODATA are empty, not errors.
	for _, n := range []string{"nothere.example.com", "dangling.example.com"} {
		if addrs, err := r.LookupA(ctx, n); err != nil || len(addrs) != 0 {
			t.Fatalf("%s: %v %v", n, addrs, err)
		}
	}
	if txt, err := r.LookupTXT(ctx, "text2.example.com"); err != nil || len(txt) != 0 {
		t.Fatalf("NODATA: %v %v", txt, err)
	}
}

func TestGETAndRcodes(t *testing.T) {
	srv := newServer(t, "", "a.example A 192.0.2.1")
	ask := func(name string) *dns.Msg {
		q := new(dns.Msg)
		q.SetQuestion(name, dns.TypeA)
		q.Id = 0
		wire, _ := q.Pack()
		resp, err := http.Get(srv.URL + "/dns-query?dns=" + base64.RawURLEncoding.EncodeToString(wire))
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != 200 || resp.Header.Get("Content-Type") != contentType {
			t.Fatalf("GET: %d %s", resp.StatusCode, resp.Header.Get("Content-Type"))
		}
		b, _ := io.ReadAll(resp.Body)
		m := new(dns.Msg)
		if err := m.Unpack(b); err != nil {
			t.Fatal(err)
		}
		return m
	}
	if m := ask("a.example."); m.Rcode != dns.RcodeSuccess || len(m.Answer) != 1 || !m.Response {
		t.Fatalf("known: %v", m)
	}
	if m := ask("b.example."); m.Rcode != dns.RcodeNameError {
		t.Fatalf("unknown: %v", m)
	}
	if resp, _ := http.Get(srv.URL + "/dns-query"); resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("GET without dns: %d", resp.StatusCode)
	}
	if resp, _ := http.Post(srv.URL+"/dns-query", "text/plain", nil); resp.StatusCode != http.StatusUnsupportedMediaType {
		t.Fatalf("POST wrong type: %d", resp.StatusCode)
	}
}

func TestUpstreamForwarding(t *testing.T) {
	ctx := context.Background()
	public := newServer(t, "", "_acme-challenge.text2.example.com TXT published", "example.com CAA 0 issue \"pki.goog\"")
	mock := newServer(t, public.URL+"/dns-query", "text2.example.com A 192.0.2.10")
	r := doh.New(nil, doh.WithEndpoints(mock.URL+"/dns-query"))
	if addrs, _ := r.LookupA(ctx, "text2.example.com"); len(addrs) != 1 {
		t.Fatalf("table answer: %v", addrs)
	}
	if txt, err := r.LookupTXT(ctx, "_acme-challenge.text2.example.com"); err != nil || !slices.Equal(txt, []string{"published"}) {
		t.Fatalf("forwarded TXT: %v %v", txt, err)
	}
	if caa, err := r.LookupCAA(ctx, "example.com"); err != nil || len(caa) != 1 {
		t.Fatalf("forwarded CAA: %v %v", caa, err)
	}
	// A failing upstream is SERVFAIL, which the resolver reports as an error.
	public.Close()
	if _, err := r.LookupTXT(ctx, "other.example.com"); err == nil {
		t.Fatal("dead upstream gave no error")
	}
}

func TestRecordParsing(t *testing.T) {
	table := records{}
	for _, bad := range []string{"x.example A", "x.example MX 10 mail.example", "x.example A not-an-ip"} {
		if err := table.add(bad, 60); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
	path := filepath.Join(t.TempDir(), "r.yaml")
	os.WriteFile(path, []byte("records:\n  - text2.example.com A 192.0.2.10\n  - example.com CAA 0 issuewild \";\"\n"), 0o600)
	if err := table.loadFile(path, 60); err != nil || len(table) != 2 {
		t.Fatalf("file: %v %d", err, len(table))
	}
	os.WriteFile(path, []byte("recrds: []\n"), 0o600)
	if err := table.loadFile(path, 60); err == nil {
		t.Fatal("unknown YAML field accepted")
	}
}
