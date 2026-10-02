package doh

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/miekg/dns"

	"tls-broker/internal/core"
	"tls-broker/internal/core/coretest"
)

// behaviour selects how a test DoH server answers.
type behaviour int

const (
	answerZone     behaviour = iota // answer from the zone data
	answerServfail                  // rcode SERVFAIL
	answerRefused                   // rcode REFUSED
	answerHTTP500                   // HTTP 500
	answerHang                      // never answer (until the client gives up)
	answerGarbage                   // body is not a DNS message
	answerTrunc                     // TC bit set
	answerWrongQ                    // answers a different question
	answerWrongCT                   // wrong Content-Type
	answerNotResp                   // QR bit clear
)

// dohServer is an RFC 8484 server over a small zone.
type dohServer struct {
	t  *testing.T
	mu sync.Mutex
	// rrs is the zone; owner names are FQDN lower case.
	rrs []dns.RR
	// partial: answer only the first step of a CNAME chain.
	partial bool
	mode    behaviour
	// failAfter > 0: answer SERVFAIL once that many queries were served.
	failAfter int
	queries   []string // "TYPE name" in arrival order
	srv       *httptest.Server
}

func newServer(t *testing.T, records ...string) *dohServer {
	t.Helper()
	s := &dohServer{t: t}
	for _, r := range records {
		rr, err := dns.NewRR(r)
		if err != nil {
			t.Fatalf("bad test record %q: %v", r, err)
		}
		s.rrs = append(s.rrs, rr)
	}
	s.srv = httptest.NewServer(http.HandlerFunc(s.serve))
	t.Cleanup(s.srv.Close)
	return s
}

func (s *dohServer) setMode(m behaviour) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.mode = m
}

func (s *dohServer) count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.queries)
}

func (s *dohServer) log() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return slices.Clone(s.queries)
}

func (s *dohServer) serve(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost || r.Header.Get("Content-Type") != contentType || r.Header.Get("Accept") != contentType {
		s.t.Errorf("bad request: %s content-type %q accept %q", r.Method, r.Header.Get("Content-Type"), r.Header.Get("Accept"))
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	body, _ := io.ReadAll(r.Body)
	q := new(dns.Msg)
	if err := q.Unpack(body); err != nil || len(q.Question) != 1 {
		s.t.Errorf("bad query: %v", err)
		http.Error(w, "bad query", http.StatusBadRequest)
		return
	}
	if q.Id != 0 || !q.RecursionDesired {
		s.t.Errorf("query id %d rd %v; want 0 and true", q.Id, q.RecursionDesired)
	}
	qn := q.Question[0]
	s.mu.Lock()
	s.queries = append(s.queries, dns.TypeToString[qn.Qtype]+" "+strings.TrimSuffix(qn.Name, "."))
	mode, partial := s.mode, s.partial
	if s.failAfter > 0 && len(s.queries) > s.failAfter {
		mode = answerServfail
	}
	s.mu.Unlock()

	resp := new(dns.Msg)
	resp.SetReply(q)
	switch mode {
	case answerHTTP500:
		http.Error(w, "boom", http.StatusInternalServerError)
		return
	case answerHang:
		<-r.Context().Done()
		return
	case answerGarbage:
		w.Header().Set("Content-Type", contentType)
		_, _ = w.Write([]byte{0x00, 0x01, 0x02})
		return
	case answerServfail:
		resp.Rcode = dns.RcodeServerFailure
	case answerRefused:
		resp.Rcode = dns.RcodeRefused
	case answerTrunc:
		resp.Truncated = true
	case answerWrongQ:
		resp.Question[0].Name = "other.example."
	case answerNotResp:
		resp.Response = false
	default:
		s.fill(resp, qn, partial)
	}
	wire, err := resp.Pack()
	if err != nil {
		s.t.Errorf("pack: %v", err)
		return
	}
	if mode == answerWrongCT {
		w.Header().Set("Content-Type", "text/html")
	} else {
		w.Header().Set("Content-Type", contentType)
	}
	_, _ = w.Write(wire)
}

// fill answers like a recursive resolver: follow CNAMEs (all of them, or
// only the first when partial), NXDOMAIN when the final name has no records.
func (s *dohServer) fill(resp *dns.Msg, q dns.Question, partial bool) {
	cur := dns.CanonicalName(q.Name)
	for steps := 0; steps < 20; steps++ {
		var found, cname []dns.RR
		exists := false
		for _, rr := range s.rrs {
			if dns.CanonicalName(rr.Header().Name) != cur {
				continue
			}
			exists = true
			switch {
			case rr.Header().Rrtype == q.Qtype:
				found = append(found, dns.Copy(rr))
			case rr.Header().Rrtype == dns.TypeCNAME:
				cname = append(cname, dns.Copy(rr))
			}
		}
		if !exists {
			resp.Rcode = dns.RcodeNameError
			return
		}
		if len(found) > 0 {
			resp.Answer = append(resp.Answer, found...)
			return
		}
		if len(cname) == 0 {
			return // NODATA
		}
		resp.Answer = append(resp.Answer, cname[0])
		if partial {
			return
		}
		cur = dns.CanonicalName(cname[0].(*dns.CNAME).Target)
	}
}

func newResolver(t *testing.T, timeout time.Duration, maxHops int, servers ...*dohServer) *Resolver {
	t.Helper()
	cfg := coretest.NewConfig()
	cfg.Resolver = core.ResolverConfig{Timeout: timeout, MaxCNAMEHops: maxHops}
	var urls []string
	for _, s := range servers {
		urls = append(urls, s.srv.URL)
	}
	return New(coretest.NewFakeConfig(cfg), WithEndpoints(urls...))
}

func addrs(ss ...string) []netip.Addr {
	var out []netip.Addr
	for _, s := range ss {
		out = append(out, netip.MustParseAddr(s))
	}
	return out
}

func TestDefaultEndpoints(t *testing.T) {
	r := New(nil)
	if !slices.Equal(r.endpoints, []string{CloudflareURL, GoogleURL}) {
		t.Fatalf("endpoints = %v", r.endpoints)
	}
	if to, hops := r.settings(); to != 5*time.Second || hops != 8 {
		t.Fatalf("settings = %v %d", to, hops)
	}
}

func TestLookupA(t *testing.T) {
	zone := []string{
		"host.example.com. 60 IN A 192.0.2.1",
		"host.example.com. 60 IN A 192.0.2.2",
		"host.example.com. 60 IN A 192.0.2.1",
		"host.example.com. 60 IN AAAA 2001:db8::1",
		"v6only.example.com. 60 IN AAAA 2001:db8::1",
		"www.example.com. 60 IN CNAME mid.example.net.",
		"mid.example.net. 60 IN CNAME HOST.example.com.",
		"dangling.example.com. 60 IN CNAME gone.example.net.",
	}
	tests := []struct {
		name    string
		partial bool
		want    []netip.Addr
		queries int
	}{
		{"host.example.com", false, addrs("192.0.2.1", "192.0.2.2"), 1},
		{"Host.Example.COM.", false, addrs("192.0.2.1", "192.0.2.2"), 1},
		{"v6only.example.com", false, nil, 1},
		{"missing.example.com", false, nil, 1},
		{"www.example.com", false, addrs("192.0.2.1", "192.0.2.2"), 1},
		{"www.example.com", true, addrs("192.0.2.1", "192.0.2.2"), 3},
		{"dangling.example.com", false, nil, 1},
		{"dangling.example.com", true, nil, 2},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			s := newServer(t, zone...)
			s.partial = tc.partial
			fb := newServer(t, zone...)
			r := newResolver(t, time.Second, 8, s, fb)
			got, err := r.LookupA(context.Background(), tc.name)
			if err != nil {
				t.Fatal(err)
			}
			if !slices.Equal(got, tc.want) {
				t.Fatalf("got %v, want %v", got, tc.want)
			}
			if s.count() != tc.queries || fb.count() != 0 {
				t.Fatalf("queries primary %v fallback %d; want %d and 0", s.log(), fb.count(), tc.queries)
			}
		})
	}
}

func TestCNAMEChainLimitAndLoop(t *testing.T) {
	chain := func(n int) []string {
		// c0 -> c1 -> ... -> cn, cn has an A record: n CNAME hops.
		var rrs []string
		for i := 0; i < n; i++ {
			rrs = append(rrs, "c"+strconv.Itoa(i)+".example.com. 60 IN CNAME c"+strconv.Itoa(i+1)+".example.com.")
		}
		return append(rrs, "c"+strconv.Itoa(n)+".example.com. 60 IN A 192.0.2.9")
	}
	for _, partial := range []bool{false, true} {
		t.Run(fmt.Sprintf("exactly the cap partial=%v", partial), func(t *testing.T) {
			s := newServer(t, chain(8)...)
			s.partial = partial
			got, err := newResolver(t, time.Second, 8, s).LookupA(context.Background(), "c0.example.com")
			if err != nil || !slices.Equal(got, addrs("192.0.2.9")) {
				t.Fatalf("got %v, %v", got, err)
			}
		})
		t.Run(fmt.Sprintf("over the cap partial=%v", partial), func(t *testing.T) {
			s := newServer(t, chain(9)...)
			s.partial = partial
			fb := newServer(t, chain(9)...)
			_, err := newResolver(t, time.Second, 8, s, fb).LookupA(context.Background(), "c0.example.com")
			if !errors.Is(err, core.ErrResolver) {
				t.Fatalf("err = %v, want ErrResolver", err)
			}
			if fb.count() != 0 {
				t.Fatal("a long chain is an answer, not a resolver failure; fallback must not be asked")
			}
		})
		t.Run(fmt.Sprintf("loop partial=%v", partial), func(t *testing.T) {
			s := newServer(t,
				"a.example.com. 60 IN CNAME b.example.com.",
				"b.example.com. 60 IN CNAME c.example.com.",
				"c.example.com. 60 IN CNAME A.example.com.")
			s.partial = partial
			_, err := newResolver(t, time.Second, 8, s).LookupA(context.Background(), "a.example.com")
			if !errors.Is(err, core.ErrResolver) || !strings.Contains(err.Error(), "loop") {
				t.Fatalf("err = %v, want loop ErrResolver", err)
			}
			if s.count() > 3 {
				t.Fatalf("loop made %d queries", s.count())
			}
		})
	}
}

func TestNoFallbackOnLegitimateAnswers(t *testing.T) {
	zone := []string{"empty.example.com. 60 IN TXT \"x\""}
	for _, name := range []string{"missing.example.com", "empty.example.com"} {
		t.Run(name, func(t *testing.T) {
			s := newServer(t, zone...)
			fb := newServer(t, "missing.example.com. 60 IN A 198.51.100.1", "empty.example.com. 60 IN A 198.51.100.1")
			got, err := newResolver(t, time.Second, 8, s, fb).LookupA(context.Background(), name)
			if err != nil || len(got) != 0 {
				t.Fatalf("got %v, %v; want empty, nil", got, err)
			}
			if fb.count() != 0 {
				t.Fatal("fallback asked after a legitimate answer")
			}
		})
	}
}

func TestFallbackOnFailure(t *testing.T) {
	zone := []string{"host.example.com. 60 IN A 192.0.2.1"}
	modes := map[string]behaviour{
		"servfail": answerServfail, "refused": answerRefused, "http500": answerHTTP500,
		"timeout": answerHang, "garbage": answerGarbage, "truncated": answerTrunc,
		"wrong question": answerWrongQ, "wrong content type": answerWrongCT, "not a response": answerNotResp,
	}
	for name, mode := range modes {
		t.Run(name, func(t *testing.T) {
			s := newServer(t, zone...)
			s.setMode(mode)
			fb := newServer(t, zone...)
			got, err := newResolver(t, 200*time.Millisecond, 8, s, fb).LookupA(context.Background(), "host.example.com")
			if err != nil || !slices.Equal(got, addrs("192.0.2.1")) {
				t.Fatalf("got %v, %v", got, err)
			}
			if s.count() != 1 || fb.count() != 1 {
				t.Fatalf("queries primary %d fallback %d; want 1 and 1", s.count(), fb.count())
			}
		})
	}
	t.Run("both down", func(t *testing.T) {
		s := newServer(t, zone...)
		s.setMode(answerServfail)
		fb := newServer(t, zone...)
		fb.setMode(answerHang)
		_, err := newResolver(t, 200*time.Millisecond, 8, s, fb).LookupA(context.Background(), "host.example.com")
		if !errors.Is(err, core.ErrResolver) {
			t.Fatalf("err = %v, want ErrResolver", err)
		}
	})
	t.Run("unreachable", func(t *testing.T) {
		s := newServer(t, zone...)
		s.srv.Close()
		fb := newServer(t, zone...)
		fb.srv.Close()
		_, err := newResolver(t, time.Second, 8, s, fb).LookupTXT(context.Background(), "host.example.com")
		if !errors.Is(err, core.ErrResolver) {
			t.Fatalf("err = %v, want ErrResolver", err)
		}
	})
	t.Run("fallback per query in a chain", func(t *testing.T) {
		chain := []string{"www.example.com. 60 IN CNAME host.example.net.", "host.example.net. 60 IN A 192.0.2.7"}
		s := newServer(t, chain...)
		s.partial = true
		fb := newServer(t, chain...)
		fb.partial = true
		s.failAfter = 1 // the primary answers the first query, then fails
		r := newResolver(t, time.Second, 8, s, fb)
		got, err := r.LookupA(context.Background(), "www.example.com")
		if err != nil || !slices.Equal(got, addrs("192.0.2.7")) {
			t.Fatalf("got %v, %v", got, err)
		}
		if !slices.Equal(fb.log(), []string{"A host.example.net"}) {
			t.Fatalf("fallback queries = %v", fb.log())
		}
	})
}

func TestContextEnds(t *testing.T) {
	s := newServer(t)
	s.setMode(answerHang)
	fb := newServer(t, "host.example.com. 60 IN A 192.0.2.1")
	r := newResolver(t, 5*time.Second, 8, s, fb)
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	_, err := r.LookupA(ctx, "host.example.com")
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("err = %v, want deadline exceeded", err)
	}
	if fb.count() != 0 {
		t.Fatal("fallback asked after the caller's context ended")
	}
}

func TestLookupTXT(t *testing.T) {
	s := newServer(t,
		`_acme-challenge.host.example.com. 60 IN TXT "abc" "def"`,
		`_acme-challenge.host.example.com. 60 IN TXT "single"`,
		`_acme-challenge.host.example.com. 60 IN TXT "q\"uote\\back\001"`,
		`_acme-challenge.alias.example.com. 60 IN CNAME _acme-challenge.host.example.com.`,
	)
	r := newResolver(t, time.Second, 8, s)
	want := []string{"abcdef", "single", "q\"uote\\back\x01"}
	for _, name := range []string{"_acme-challenge.host.example.com", "_acme-challenge.alias.example.com"} {
		got, err := r.LookupTXT(context.Background(), name)
		if err != nil || !slices.Equal(got, want) {
			t.Fatalf("%s: got %q, %v; want %q", name, got, err, want)
		}
	}
	got, err := r.LookupTXT(context.Background(), "_acme-challenge.none.example.com")
	if err != nil || len(got) != 0 {
		t.Fatalf("missing: got %q, %v", got, err)
	}
}

func TestLookupCAA(t *testing.T) {
	s := newServer(t,
		`example.com. 60 IN CAA 0 issue "letsencrypt.org; accounturi=https://acme-v02.api.letsencrypt.org/acme/acct/1"`,
		`example.com. 60 IN CAA 128 ISSUEWILD ";"`,
		`sub.example.com. 60 IN A 192.0.2.1`,
		`alias.example.com. 60 IN CNAME target.example.net.`,
		`target.example.net. 60 IN CAA 0 issue "pki.goog"`,
	)
	r := newResolver(t, time.Second, 8, s)
	got, err := r.LookupCAA(context.Background(), "example.com")
	want := []core.CAA{
		{Flag: 0, Tag: "issue", Value: "letsencrypt.org; accounturi=https://acme-v02.api.letsencrypt.org/acme/acct/1"},
		{Flag: 128, Tag: "issuewild", Value: ";"},
	}
	if err != nil || !slices.Equal(got, want) {
		t.Fatalf("apex: got %+v, %v", got, err)
	}
	// No climbing: the child has no CAA of its own.
	if got, err := r.LookupCAA(context.Background(), "sub.example.com"); err != nil || len(got) != 0 {
		t.Fatalf("child: got %+v, %v", got, err)
	}
	// A CNAME at the node is followed.
	got, err = r.LookupCAA(context.Background(), "alias.example.com")
	if err != nil || !slices.Equal(got, []core.CAA{{Tag: "issue", Value: "pki.goog"}}) {
		t.Fatalf("alias: got %+v, %v", got, err)
	}
}

func TestInvalidName(t *testing.T) {
	s := newServer(t)
	r := newResolver(t, time.Second, 8, s)
	for _, n := range []string{"", ".", "a..b"} {
		if _, err := r.LookupA(context.Background(), n); !errors.Is(err, core.ErrResolver) {
			t.Fatalf("%q: err = %v", n, err)
		}
	}
	if s.count() != 0 {
		t.Fatal("invalid names must not be sent")
	}
}

func TestUnescapeTXT(t *testing.T) {
	for in, want := range map[string]string{
		`plain`: "plain", `a\"b`: `a"b`, `a\\b`: `a\b`, `\000\255`: "\x00\xff", `\;x`: ";x",
	} {
		if got := unescapeTXT(in); got != want {
			t.Errorf("unescapeTXT(%q) = %q, want %q", in, got, want)
		}
	}
}
