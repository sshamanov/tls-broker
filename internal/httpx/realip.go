// Package httpx is the HTTP plumbing shared by every front end: the real
// source IPv4 (architecture §19), request ID, panic recovery, access logging,
// body and time limits, RFC 7807 / ACME problem responses and /healthz.
//
// Middleware order, outermost first: Recover, RealIP, RequestID, AccessLog,
// then per-route MaxBody and PathTimeouts.
package httpx

import (
	"context"
	"net"
	"net/http"
	"net/netip"
	"strings"
)

// DefaultProtoHeader is the header consulted for "the client used https" when
// the peer is a trusted proxy and Options.ProtoHeader is empty.
const DefaultProtoHeader = "X-Forwarded-Proto"

// Flags describing why a Client has no usable IPv4 address.
const (
	FlagNone          = ""
	FlagPeerNotIPv4   = "peer_not_ipv4"   // the TCP peer is not an IPv4 address
	FlagHeaderInvalid = "header_invalid"  // trusted proxy sent several values or an unparsable one
	FlagHeaderNotIPv4 = "header_not_ipv4" // trusted proxy sent a valid non-IPv4 address
	FlagHeaderMissing = "header_missing"  // trusted proxy sent no real-IP header; the peer is used
)

// Client describes where a request came from.
type Client struct {
	// IP is the real source IPv4 address (IPv4-mapped IPv6 unmapped). The
	// zero Addr means no usable IPv4 source; see Flag. Callers must treat
	// an invalid IP as a denial (core.ReasonNotIPv4).
	IP netip.Addr
	// Peer is the TCP peer address, unmapped, zero if unparsable.
	Peer netip.Addr
	// Trusted reports that the TCP peer is inside the trusted-proxy
	// prefixes, so the real-IP and proto headers were believed.
	Trusted bool
	// HTTPS reports that the client connection used TLS: the request
	// itself was TLS, or a trusted proxy said so in the proto header.
	HTTPS bool
	// Flag explains an invalid IP or a questionable header; FlagNone when
	// all is well.
	Flag string
}

// Valid reports whether IP is a usable IPv4 address.
func (c Client) Valid() bool { return c.IP.IsValid() }

// Options configure a Resolver (from core.ServerConfig).
type Options struct {
	// TrustedProxies are the peers whose headers are believed. Empty:
	// never trust any header.
	TrustedProxies []netip.Prefix
	// RealIPHeader is the single header carrying the client address.
	// Empty disables header use.
	RealIPHeader string
	// ProtoHeader carries the original scheme; empty means
	// DefaultProtoHeader.
	ProtoHeader string
}

// Resolver derives Client from a request.
type Resolver struct {
	trusted         []netip.Prefix
	ipHeader, proto string
}

// NewResolver builds a Resolver. Prefixes are normalized: IPv4-mapped IPv6
// prefixes are converted to IPv4.
func NewResolver(o Options) *Resolver {
	r := &Resolver{ipHeader: http.CanonicalHeaderKey(strings.TrimSpace(o.RealIPHeader)), proto: o.ProtoHeader}
	if r.proto == "" {
		r.proto = DefaultProtoHeader
	}
	r.proto = http.CanonicalHeaderKey(r.proto)
	for _, p := range o.TrustedProxies {
		if p.Addr().Is4In6() && p.Bits() >= 96 {
			p = netip.PrefixFrom(p.Addr().Unmap(), p.Bits()-96)
		}
		r.trusted = append(r.trusted, p.Masked())
	}
	return r
}

func (r *Resolver) isTrusted(a netip.Addr) bool {
	for _, p := range r.trusted {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

// Resolve returns the Client of req. The real-IP header is used only when the
// TCP peer is a trusted proxy; otherwise the peer address is the source and
// every forwarding header is ignored. X-Forwarded-For is never read.
func (r *Resolver) Resolve(req *http.Request) Client {
	c := Client{HTTPS: req.TLS != nil}
	host := req.RemoteAddr
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	peer, err := netip.ParseAddr(strings.TrimSpace(host))
	if err != nil {
		c.Flag = FlagPeerNotIPv4
		return c
	}
	peer = peer.WithZone("").Unmap()
	c.Peer = peer
	if r.isTrusted(peer) {
		c.Trusted = true
		return r.fromHeader(req, c)
	}
	if !peer.Is4() {
		c.Flag = FlagPeerNotIPv4
		return c
	}
	c.IP = peer
	return c
}

func (r *Resolver) fromHeader(req *http.Request, c Client) Client {
	if v := req.Header.Values(r.proto); len(v) == 1 {
		c.HTTPS = c.HTTPS || strings.EqualFold(strings.TrimSpace(v[0]), "https")
	}
	if r.ipHeader == "" {
		c.IP = c.Peer
		return c
	}
	vals := req.Header.Values(r.ipHeader)
	switch {
	case len(vals) == 0 || (len(vals) == 1 && strings.TrimSpace(vals[0]) == ""):
		// Misconfigured proxy: attribute to the proxy itself, flagged.
		c.Flag = FlagHeaderMissing
		if c.Peer.Is4() {
			c.IP = c.Peer
		}
		return c
	case len(vals) > 1:
		c.Flag = FlagHeaderInvalid // exactly one value is allowed
		return c
	}
	a, err := netip.ParseAddr(strings.TrimSpace(vals[0]))
	if err != nil || a.Zone() != "" {
		c.Flag = FlagHeaderInvalid
		return c
	}
	a = a.Unmap()
	if !a.Is4() {
		c.Flag = FlagHeaderNotIPv4
		return c
	}
	c.IP = a
	return c
}

type ctxKey int

const (
	clientKey ctxKey = iota
	requestIDKey
)

// WithClient returns ctx carrying c.
func WithClient(ctx context.Context, c Client) context.Context {
	return context.WithValue(ctx, clientKey, c)
}

// ClientFrom returns the Client the RealIP middleware stored; the zero Client
// (invalid IP) when there is none.
func ClientFrom(ctx context.Context) Client {
	c, _ := ctx.Value(clientKey).(Client)
	return c
}

// SourceIP returns the real source IPv4 of the request and whether it is
// usable. Callers treat false as a denial.
func SourceIP(ctx context.Context) (netip.Addr, bool) {
	c := ClientFrom(ctx)
	return c.IP, c.Valid()
}

// IsHTTPS reports whether the client connection used https (directly or as
// told by a trusted proxy).
func IsHTTPS(ctx context.Context) bool { return ClientFrom(ctx).HTTPS }

// RealIP is middleware that resolves the Client and stores it in the request
// context.
func RealIP(r *Resolver) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			next.ServeHTTP(w, req.WithContext(WithClient(req.Context(), r.Resolve(req))))
		})
	}
}

// RequireIPv4 is middleware that answers 403 when there is no usable source
// IPv4 address. Front ends that need the source for authorization put it
// after RealIP; /healthz and the UI login page normally do not use it.
func RequireIPv4(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if _, ok := SourceIP(req.Context()); !ok {
			WriteProblemStatus(w, http.StatusForbidden, "urn:ietf:params:acme:error:unauthorized",
				"the source address is not a usable IPv4 address")
			return
		}
		next.ServeHTTP(w, req)
	})
}
