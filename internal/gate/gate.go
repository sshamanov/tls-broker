// Package gate makes the authorization decision for all three issuance modes
// (architecture §3.1, §3.2, §3.3, §4.2, §16) and reports the CAA wildcard
// protection status of managed zones for the UI.
//
// The gate reads only grants and public DNS. It never looks at a grant's
// owner: a grant is a capability object whose effect depends on its own
// fields. It writes no audit records; callers do, with the Decision.
package gate

import (
	"cmp"
	"context"
	"fmt"
	"net/netip"
	"slices"
	"strings"

	"tls-broker/internal/core"
	"tls-broker/internal/names"
)

// Gate implements core.Gate and core.CAAChecker. It is safe for concurrent
// use and holds no state of its own: configuration is read from the source
// on every call, grants from the store, DNS from the resolver.
type Gate struct {
	cfg       core.ConfigSource
	grants    core.GrantStore
	resolver  core.Resolver
	providers core.Providers
}

var (
	_ core.Gate       = (*Gate)(nil)
	_ core.CAAChecker = (*Gate)(nil)
)

// New returns a gate. providers is needed for the DNS-proxy CAA check and
// for CheckCAA (issuer domains, accounturi support and account URLs).
func New(cfg core.ConfigSource, grants core.GrantStore, resolver core.Resolver, providers core.Providers) *Gate {
	return &Gate{cfg: cfg, grants: grants, resolver: resolver, providers: providers}
}

func deny(reason, name, detail string) core.Decision {
	return core.Decision{Allowed: false, Reason: reason, Name: name, Detail: detail}
}

// Authorize implements core.Gate.
func (g *Gate) Authorize(ctx context.Context, mode core.Mode, src netip.Addr, set names.Set) (core.Decision, error) {
	if err := ctx.Err(); err != nil {
		return core.Decision{}, err
	}
	switch mode {
	case core.ModeACME, core.ModeDirect, core.ModeDNSProxy:
	default:
		return core.Decision{}, fmt.Errorf("gate: mode %q does not issue certificates", mode)
	}

	// 1. Source and names.
	src = src.Unmap()
	if !src.Is4() {
		return deny(core.ReasonNotIPv4, "", fmt.Sprintf("source %v is not an IPv4 address", src)), nil
	}
	if set.IsZero() {
		return deny(core.ReasonInvalidIdentifier, "", "no identifiers"), nil
	}
	if name, outside := g.cfg.Current().ManagedZones().FirstOutside(set); outside {
		return deny(core.ReasonOutsideManagedZone, name, "not inside any managed zone"), nil
	}

	// 2. Grants, before any DNS query.
	grant, err := g.matchGrant(ctx, src)
	if err != nil {
		return core.Decision{}, err
	}
	var d core.Decision
	switch {
	case grant != nil && grant.Wildcard:
		// A wildcard grant permits everything and skips the CAA check.
		return core.Decision{Allowed: true, Reason: core.ReasonIPGrant, GrantID: grant.ID,
			Detail: fmt.Sprintf("wildcard grant %d for %s", grant.ID, grant.Prefix)}, nil
	case set.HasWildcard():
		detail := "wildcard identifiers need a grant with wildcard=true; no grant matches " + src.String()
		if grant != nil {
			detail = fmt.Sprintf("grant %d for %s does not permit wildcards", grant.ID, grant.Prefix)
		}
		return deny(core.ReasonWildcardGrantRequired, set.Wildcards()[0], detail), nil
	case grant != nil:
		d = core.Decision{Allowed: true, Reason: core.ReasonIPGrant, GrantID: grant.ID,
			Detail: fmt.Sprintf("grant %d for %s", grant.ID, grant.Prefix)}
	default:
		// 3. DNS gate: every name must resolve to the source.
		d, err = g.dnsGate(ctx, src, set)
		if err != nil || !d.Allowed {
			return d, err
		}
	}

	// 4. DNS proxy without a wildcard grant: a TXT record at
	// _acme-challenge.N also validates *.N, so public CAA must already keep
	// foreign ACME accounts away from *.N.
	if mode == core.ModeDNSProxy {
		ev := g.newEval()
		for _, name := range set.Names() {
			st, err := ev.status(ctx, name, false)
			if err != nil {
				if ctxErr := ctx.Err(); ctxErr != nil {
					return core.Decision{}, ctxErr
				}
				return deny(core.ReasonDNSFailure, name, "CAA lookup failed: "+err.Error()), nil
			}
			if !st.WildcardProtected {
				return deny(core.ReasonWildcardUnprotected, name, st.Detail), nil
			}
		}
	}
	return d, nil
}

// matchGrant returns the grant that applies to src, or nil. A wildcard grant
// wins over an ordinary one; among equals the longest prefix, then the lowest
// ID. Disabled grants and grants not covering src are ignored even if the
// store returned them.
func (g *Gate) matchGrant(ctx context.Context, src netip.Addr) (*core.Grant, error) {
	list, err := g.grants.Match(ctx, src)
	if err != nil {
		return nil, fmt.Errorf("gate: matching grants for %s: %w", src, err)
	}
	var best *core.Grant
	for i := range list {
		gr := &list[i]
		if !gr.Enabled || !gr.Prefix.IsValid() || !gr.Prefix.Addr().Is4() || !gr.Prefix.Masked().Contains(src) {
			continue
		}
		if best == nil || better(gr, best) {
			best = gr
		}
	}
	if best == nil {
		return nil, nil
	}
	out := *best
	return &out, nil
}

func better(a, b *core.Grant) bool {
	if a.Wildcard != b.Wildcard {
		return a.Wildcard
	}
	if c := cmp.Compare(a.Prefix.Bits(), b.Prefix.Bits()); c != 0 {
		return c > 0
	}
	return a.ID < b.ID
}

// dnsGate allows when every name resolves (A, following CNAMEs) to src. The
// first name that does not decides the denial. It never attributes the
// decision to a grant.
func (g *Gate) dnsGate(ctx context.Context, src netip.Addr, set names.Set) (core.Decision, error) {
	for _, name := range set.Names() {
		addrs, err := g.resolver.LookupA(ctx, name)
		if err != nil {
			if ctxErr := ctx.Err(); ctxErr != nil {
				return core.Decision{}, ctxErr
			}
			return deny(core.ReasonDNSFailure, name, err.Error()), nil
		}
		if !slices.Contains(addrs, src) {
			detail := "no A records"
			if len(addrs) > 0 {
				detail = "resolves to " + joinAddrs(addrs) + ", not " + src.String()
			}
			return deny(core.ReasonDNSMismatch, name, detail), nil
		}
	}
	detail := "every name resolves to " + src.String()
	if set.Len() == 1 {
		detail = set.Names()[0] + " resolves to " + src.String()
	}
	return core.Decision{Allowed: true, Reason: core.ReasonDNSIPMatch, Detail: detail}, nil
}

func joinAddrs(addrs []netip.Addr) string {
	s := make([]string, len(addrs))
	for i, a := range addrs {
		s[i] = a.String()
	}
	return strings.Join(s, ", ")
}
