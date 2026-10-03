// Package doh is the broker's view of public DNS: a core.Resolver over
// DNS-over-HTTPS (RFC 8484) with Cloudflare as the primary and Google as the
// fallback resolver (architecture §16).
//
// Rules:
//   - The endpoints are fixed. WithEndpoints exists for tests and for the
//     development-only TLS_BROKER_DOH_ENDPOINTS override (a mocked DNS gate).
//   - The fallback is asked only when the previous resolver failed: transport
//     error, timeout, non-200 HTTP answer, a response that is not a valid DNS
//     answer to the question (malformed, truncated, wrong question), or a
//     server rcode such as SERVFAIL or REFUSED. A legitimate answer (NOERROR,
//     with or without records, or NXDOMAIN) is final.
//   - There is no cache: every lookup asks the network.
//   - CNAME chains are followed within one answer and, when the answer stops
//     before the end of the chain, by asking again for the last target. The
//     chain length is capped (ResolverConfig.MaxCNAMEHops) and loops are
//     detected; both give an error matching core.ErrResolver.
package doh

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"strings"
	"time"

	"github.com/miekg/dns"

	"tls-broker/internal/core"
)

// The fixed DoH endpoints, in order of preference (architecture §16).
const (
	CloudflareURL = "https://cloudflare-dns.com/dns-query"
	GoogleURL     = "https://dns.google/dns-query"
)

const (
	contentType     = "application/dns-message"
	maxResponseSize = 65535 // a DNS message cannot be larger
	defaultTimeout  = 5 * time.Second
	defaultMaxHops  = 8
)

// Resolver implements core.Resolver over DoH. It is safe for concurrent use.
type Resolver struct {
	cfg       core.ConfigSource
	endpoints []string
	client    *http.Client
}

var _ core.Resolver = (*Resolver)(nil)

// Option configures a Resolver.
type Option func(*Resolver)

// WithEndpoints replaces the DoH endpoints (tried in order). For tests and
// the development-only TLS_BROKER_DOH_ENDPOINTS override: production always
// uses CloudflareURL then GoogleURL.
func WithEndpoints(urls ...string) Option {
	return func(r *Resolver) { r.endpoints = append([]string(nil), urls...) }
}

// WithHTTPClient sets the HTTP client (for example one trusting a test
// server's certificate). Its own Timeout should be zero; the per-request
// timeout comes from the configuration.
func WithHTTPClient(c *http.Client) Option {
	return func(r *Resolver) { r.client = c }
}

// New returns a resolver. The per-request timeout and the CNAME hop limit are
// read from cfg.Current().Resolver on every lookup, so configuration reloads
// apply at once; zero values fall back to 5 s and 8 hops.
func New(cfg core.ConfigSource, opts ...Option) *Resolver {
	r := &Resolver{
		cfg:       cfg,
		endpoints: []string{CloudflareURL, GoogleURL},
		client:    &http.Client{},
	}
	for _, o := range opts {
		o(r)
	}
	return r
}

func (r *Resolver) settings() (timeout time.Duration, maxHops int) {
	timeout, maxHops = defaultTimeout, defaultMaxHops
	if r.cfg == nil {
		return
	}
	if c := r.cfg.Current(); c != nil {
		if c.Resolver.Timeout > 0 {
			timeout = c.Resolver.Timeout
		}
		if c.Resolver.MaxCNAMEHops > 0 {
			maxHops = c.Resolver.MaxCNAMEHops
		}
	}
	return
}

// LookupA implements core.Resolver.
func (r *Resolver) LookupA(ctx context.Context, name string) ([]netip.Addr, error) {
	rrs, err := r.lookup(ctx, name, dns.TypeA)
	if err != nil {
		return nil, err
	}
	var out []netip.Addr
	seen := map[netip.Addr]bool{}
	for _, rr := range rrs {
		a, ok := rr.(*dns.A)
		if !ok {
			continue
		}
		addr, ok := netip.AddrFromSlice(a.A.To4())
		if !ok || seen[addr] {
			continue
		}
		seen[addr] = true
		out = append(out, addr)
	}
	return out, nil
}

// LookupTXT implements core.Resolver.
func (r *Resolver) LookupTXT(ctx context.Context, name string) ([]string, error) {
	rrs, err := r.lookup(ctx, name, dns.TypeTXT)
	if err != nil {
		return nil, err
	}
	var out []string
	for _, rr := range rrs {
		t, ok := rr.(*dns.TXT)
		if !ok {
			continue
		}
		var b strings.Builder
		for _, s := range t.Txt {
			b.WriteString(unescapeTXT(s))
		}
		out = append(out, b.String())
	}
	return out, nil
}

// LookupCAA implements core.Resolver. A CNAME at the node is followed (RFC
// 8659 §3: the CAA RRset of a name is what a normal query for it returns);
// the tree is not climbed.
func (r *Resolver) LookupCAA(ctx context.Context, name string) ([]core.CAA, error) {
	rrs, err := r.lookup(ctx, name, dns.TypeCAA)
	if err != nil {
		return nil, err
	}
	var out []core.CAA
	for _, rr := range rrs {
		c, ok := rr.(*dns.CAA)
		if !ok {
			continue
		}
		out = append(out, core.CAA{Flag: c.Flag, Tag: strings.ToLower(c.Tag), Value: c.Value})
	}
	return out, nil
}

// lookup returns the records of qtype at the end of the CNAME chain starting
// at name. NXDOMAIN and NODATA give an empty result.
func (r *Resolver) lookup(ctx context.Context, name string, qtype uint16) ([]dns.RR, error) {
	start := dns.CanonicalName(name)
	if _, ok := dns.IsDomainName(start); !ok || start == "." {
		return nil, fmt.Errorf("%w: invalid name %q", core.ErrResolver, name)
	}
	timeout, maxHops := r.settings()
	cur := start
	seen := map[string]bool{cur: true}
	hops := 0
	for {
		msg, err := r.exchange(ctx, cur, qtype, timeout)
		if err != nil {
			return nil, err
		}
		// Walk the answer section from cur along CNAMEs.
		queried := cur
		for {
			if rrs := recordsAt(msg.Answer, cur, qtype); len(rrs) > 0 {
				return rrs, nil
			}
			target, ok := cnameAt(msg.Answer, cur)
			if !ok {
				break
			}
			if hops >= maxHops {
				return nil, fmt.Errorf("%w: CNAME chain from %s is longer than %d", core.ErrResolver, trim(start), maxHops)
			}
			if seen[target] {
				return nil, fmt.Errorf("%w: CNAME loop at %s", core.ErrResolver, trim(target))
			}
			hops++
			seen[target] = true
			cur = target
		}
		// No records at cur in this answer. If the answer covered the name we
		// asked about, that is the final result (NXDOMAIN or NODATA; the rcode
		// refers to the end of the chain, RFC 6604). Otherwise the answer
		// stopped part way along the chain: ask for the last target.
		if cur == queried || msg.Rcode == dns.RcodeNameError {
			return nil, nil
		}
	}
}

func recordsAt(answer []dns.RR, owner string, qtype uint16) []dns.RR {
	var out []dns.RR
	for _, rr := range answer {
		h := rr.Header()
		if h.Rrtype == qtype && h.Class == dns.ClassINET && dns.CanonicalName(h.Name) == owner {
			out = append(out, rr)
		}
	}
	return out
}

func cnameAt(answer []dns.RR, owner string) (string, bool) {
	for _, rr := range answer {
		if c, ok := rr.(*dns.CNAME); ok && c.Hdr.Class == dns.ClassINET && dns.CanonicalName(c.Hdr.Name) == owner {
			return dns.CanonicalName(c.Target), true
		}
	}
	return "", false
}

// exchange asks each endpoint in turn and returns the first legitimate
// answer. When ctx ends it returns ctx's error without trying further.
func (r *Resolver) exchange(ctx context.Context, fqdn string, qtype uint16, timeout time.Duration) (*dns.Msg, error) {
	q := new(dns.Msg)
	q.SetQuestion(fqdn, qtype)
	q.Id = 0 // RFC 8484 §4.1
	q.RecursionDesired = true
	q.SetEdns0(4096, false)
	wire, err := q.Pack()
	if err != nil {
		return nil, fmt.Errorf("%w: packing query for %s: %v", core.ErrResolver, trim(fqdn), err)
	}
	var errs []error
	for _, ep := range r.endpoints {
		msg, err := r.ask(ctx, ep, wire, fqdn, qtype, timeout)
		if err == nil {
			return msg, nil
		}
		if ctxErr := ctx.Err(); ctxErr != nil {
			return nil, ctxErr
		}
		errs = append(errs, fmt.Errorf("%s: %w", ep, err))
	}
	return nil, fmt.Errorf("%w: %s %s: %w", core.ErrResolver, dns.TypeToString[qtype], trim(fqdn), errors.Join(errs...))
}

// ask performs one DoH POST and validates the answer.
func (r *Resolver) ask(ctx context.Context, endpoint string, wire []byte, fqdn string, qtype uint16, timeout time.Duration) (*dns.Msg, error) {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(wire))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", contentType)
	req.Header.Set("Accept", contentType)
	resp, err := r.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, maxResponseSize))
		return nil, fmt.Errorf("HTTP status %d", resp.StatusCode)
	}
	if ct := resp.Header.Get("Content-Type"); !strings.HasPrefix(strings.ToLower(ct), contentType) {
		return nil, fmt.Errorf("unexpected content type %q", ct)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseSize+1))
	if err != nil {
		return nil, err
	}
	if len(body) > maxResponseSize {
		return nil, errors.New("response too large")
	}
	msg := new(dns.Msg)
	if err := msg.Unpack(body); err != nil {
		return nil, fmt.Errorf("malformed response: %v", err)
	}
	switch {
	case !msg.Response:
		return nil, errors.New("not a response")
	case msg.Truncated:
		return nil, errors.New("truncated response")
	case len(msg.Question) != 1 || dns.CanonicalName(msg.Question[0].Name) != fqdn ||
		msg.Question[0].Qtype != qtype || msg.Question[0].Qclass != dns.ClassINET:
		return nil, errors.New("response does not match the question")
	}
	switch msg.Rcode {
	case dns.RcodeSuccess, dns.RcodeNameError:
		return msg, nil
	default:
		return nil, fmt.Errorf("rcode %s", dns.RcodeToString[msg.Rcode])
	}
}

// unescapeTXT turns a character-string as miekg/dns presents it (with \" ,
// \\ and \DDD escapes) back into its raw bytes.
func unescapeTXT(s string) string {
	if !strings.Contains(s, `\`) {
		return s
	}
	b := make([]byte, 0, len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c != '\\' || i+1 == len(s) {
			b = append(b, c)
			continue
		}
		i++
		if i+2 < len(s) && isDigit(s[i]) && isDigit(s[i+1]) && isDigit(s[i+2]) {
			b = append(b, (s[i]-'0')*100+(s[i+1]-'0')*10+(s[i+2]-'0'))
			i += 2
			continue
		}
		b = append(b, s[i])
	}
	return string(b)
}

func isDigit(c byte) bool { return c >= '0' && c <= '9' }

func trim(fqdn string) string { return strings.TrimSuffix(fqdn, ".") }
