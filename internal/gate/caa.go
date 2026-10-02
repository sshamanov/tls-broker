package gate

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"

	"tls-broker/internal/core"
	"tls-broker/internal/names"
)

// CheckCAA implements core.CAAChecker. A wildcard name is checked as its
// base name (the CAA RRset of "*.N" is the one of N).
func (g *Gate) CheckCAA(ctx context.Context, name string) (core.CAAStatus, error) {
	return g.newEval().status(ctx, name, true)
}

// eval is one evaluation: it remembers CAA RRsets and account URLs for the
// duration of a single call so a multi-name request asks for each node once.
// Nothing outlives the call.
type eval struct {
	g        *Gate
	enabled  []core.Provider
	rrsets   map[string][]core.CAA
	accounts map[string]accountResult
}

type accountResult struct {
	url string
	err error
}

func (g *Gate) newEval() *eval {
	var enabled []core.Provider
	if g.providers != nil {
		enabled = g.providers.Enabled()
	}
	return &eval{g: g, enabled: enabled, rrsets: map[string][]core.CAA{}, accounts: map[string]accountResult{}}
}

// effective climbs from name towards the root (RFC 8659 §3) and returns the
// first node with a non-empty CAA RRset. The resolver follows a CNAME at a
// node itself; the climb continues from the original name's parent, never
// from the CNAME target's.
func (e *eval) effective(ctx context.Context, name string) (node string, rrset []core.CAA, err error) {
	for n := name; n != ""; n = parent(n) {
		rrs, ok := e.rrsets[n]
		if !ok {
			rrs, err = e.g.resolver.LookupCAA(ctx, n)
			if err != nil {
				return "", nil, fmt.Errorf("CAA %s: %w", n, err)
			}
			e.rrsets[n] = rrs
		}
		if len(rrs) > 0 {
			return n, rrs, nil
		}
	}
	return "", nil, nil
}

func parent(name string) string {
	if i := strings.IndexByte(name, '.'); i >= 0 {
		return name[i+1:]
	}
	return ""
}

// status evaluates the CAA wildcard protection of name. withProviders also
// fills MissingProviders (UI only). The error is non-nil only when DNS
// resolution failed or ctx ended.
func (e *eval) status(ctx context.Context, name string, withProviders bool) (core.CAAStatus, error) {
	name = names.Base(strings.TrimSuffix(strings.ToLower(name), "."))
	st := core.CAAStatus{Name: name}
	node, rrset, err := e.effective(ctx, name)
	if err != nil {
		return st, err
	}
	st.Node, st.Records = node, slices.Clone(rrset)

	protected, detail, err := e.protected(ctx, name, node, rrset)
	if err != nil {
		return st, err
	}
	st.WildcardProtected, st.Detail = protected, detail
	if withProviders {
		missing, err := e.missing(ctx, rrset)
		if err != nil {
			return st, err
		}
		st.MissingProviders = missing
	}
	return st, nil
}

// wildcardSet returns the properties CAs apply to "*.N": issuewild if the
// RRset has any, otherwise issue (RFC 8659 §4.3).
func wildcardSet(rrset []core.CAA) (tag string, values []string) {
	for _, tag := range []string{"issuewild", "issue"} {
		for _, r := range rrset {
			if strings.EqualFold(r.Tag, tag) {
				values = append(values, r.Value)
			}
		}
		if len(values) > 0 {
			return tag, values
		}
	}
	return "", nil
}

// protected is the architecture §3.2 verdict: every value that applies to
// "*.N" is either ";" (no CA) or names an enabled provider that honours RFC
// 8657 accounturi and is pinned to the broker's own account there.
func (e *eval) protected(ctx context.Context, name, node string, rrset []core.CAA) (bool, string, error) {
	if node == "" {
		return false, fmt.Sprintf("no CAA records for %s or any parent: any CA may issue *.%s", name, name), nil
	}
	tag, values := wildcardSet(rrset)
	if tag == "" {
		return false, fmt.Sprintf("CAA at %s has no issue or issuewild property: any CA may issue *.%s", node, name), nil
	}
	var pinned []string
	for _, raw := range values {
		v, err := parseIssueValue(raw)
		if err != nil {
			return false, fmt.Sprintf("CAA %s %q at %s: %v", tag, raw, node, err), nil
		}
		if v.issuer == "" {
			continue // forbids every CA
		}
		ok, why, err := e.pinnedToBroker(ctx, v)
		if err != nil {
			return false, "", err
		}
		if !ok {
			return false, fmt.Sprintf("CAA %s %q at %s: %s", tag, raw, node, why), nil
		}
		pinned = append(pinned, v.issuer)
	}
	if len(pinned) == 0 {
		return true, fmt.Sprintf("CAA %s at %s forbids every CA for *.%s", tag, node, name), nil
	}
	return true, fmt.Sprintf("CAA %s at %s allows *.%s only to the broker's accounts at %s", tag, node, name, strings.Join(pinned, ", ")), nil
}

// pinnedToBroker reports whether a value with an issuer domain can only be
// used by the broker: the issuer belongs to an enabled provider that honours
// accounturi, and every accounturi parameter (at least one) equals that
// provider's account URL.
func (e *eval) pinnedToBroker(ctx context.Context, v issueValue) (bool, string, error) {
	cands := e.providersFor(v.issuer)
	if len(cands) == 0 {
		return false, fmt.Sprintf("issuer %s is not an enabled provider", v.issuer), nil
	}
	if v.badAccountTag {
		return false, "accounturi parameter must be spelled in lower case", nil
	}
	if len(v.accountURIs) == 0 {
		return false, fmt.Sprintf("issuer %s is not pinned with accounturi", v.issuer), nil
	}
	honoured := false
	var acctErr error
	for _, p := range cands {
		if !p.Caps().AccountURIHonoured {
			continue
		}
		honoured = true
		acct, err := e.account(ctx, p)
		if err != nil {
			if ctxErr := ctx.Err(); ctxErr != nil {
				return false, "", ctxErr
			}
			acctErr = err
			continue
		}
		if allEqual(v.accountURIs, acct) {
			return true, "", nil
		}
	}
	if acctErr != nil {
		return false, fmt.Sprintf("the broker's account at %s is unknown: %v", v.issuer, acctErr), nil
	}
	if !honoured {
		return false, fmt.Sprintf("provider for issuer %s does not honour accounturi", v.issuer), nil
	}
	return false, fmt.Sprintf("accounturi is not the broker's account at %s", v.issuer), nil
}

func allEqual(list []string, want string) bool {
	for _, s := range list {
		if s != want {
			return false
		}
	}
	return len(list) > 0
}

func (e *eval) providersFor(issuer string) []core.Provider {
	var out []core.Provider
	for _, p := range e.enabled {
		for _, d := range p.Caps().CAAIssuers {
			if strings.EqualFold(strings.TrimSuffix(d, "."), issuer) {
				out = append(out, p)
				break
			}
		}
	}
	return out
}

func (e *eval) account(ctx context.Context, p core.Provider) (string, error) {
	if r, ok := e.accounts[p.Name()]; ok {
		return r.url, r.err
	}
	url, err := p.AccountURL(ctx)
	if ctx.Err() == nil {
		e.accounts[p.Name()] = accountResult{url, err}
	}
	return url, err
}

// missing lists the enabled providers the CAA RRset does not let the broker
// use: for non-wildcard names (issue) or, unless the wildcard set forbids
// every CA, for wildcards (issuewild, else issue).
func (e *eval) missing(ctx context.Context, rrset []core.CAA) ([]string, error) {
	var issue []string
	for _, r := range rrset {
		if strings.EqualFold(r.Tag, "issue") {
			issue = append(issue, r.Value)
		}
	}
	_, wild := wildcardSet(rrset)
	wildForbidsAll := len(wild) > 0
	for _, raw := range wild {
		if v, err := parseIssueValue(raw); err != nil || v.issuer != "" {
			wildForbidsAll = false
		}
	}
	var out []string
	for _, p := range e.enabled {
		ok, err := e.permits(ctx, p, issue)
		if err != nil {
			return nil, err
		}
		if ok && !wildForbidsAll {
			ok, err = e.permits(ctx, p, wild)
			if err != nil {
				return nil, err
			}
		}
		if !ok {
			out = append(out, p.Name())
		}
	}
	return out, nil
}

// permits reports whether a property set lets the broker's account at p
// issue. No properties at all means any CA may issue.
func (e *eval) permits(ctx context.Context, p core.Provider, values []string) (bool, error) {
	if len(values) == 0 {
		return true, nil
	}
	caps := p.Caps()
	for _, raw := range values {
		v, err := parseIssueValue(raw)
		if err != nil || v.issuer == "" || !slices.ContainsFunc(caps.CAAIssuers, func(d string) bool {
			return strings.EqualFold(strings.TrimSuffix(d, "."), v.issuer)
		}) {
			continue
		}
		if len(v.accountURIs) == 0 || !caps.AccountURIHonoured {
			return true, nil
		}
		acct, err := e.account(ctx, p)
		if err != nil {
			if ctxErr := ctx.Err(); ctxErr != nil {
				return false, ctxErr
			}
			continue
		}
		if allEqual(v.accountURIs, acct) {
			return true, nil
		}
	}
	return false, nil
}

// issueValue is a parsed CAA issue / issuewild value (RFC 8659 §4.2,
// RFC 8657 §3).
type issueValue struct {
	issuer      string   // lower case; empty means "no CA"
	accountURIs []string // every accounturi parameter, in order
	// badAccountTag: a parameter named accounturi in another case. Treated
	// as unpinned because a CA may not recognize it.
	badAccountTag bool
}

var errMalformed = errors.New("malformed value")

// parseIssueValue parses
//
//	issue-value = *WSP [issuer-domain-name *WSP] [";" *WSP [parameters *WSP]]
//	parameters  = parameter *(*WSP ";" *WSP parameter)
//	parameter   = tag *WSP "=" *WSP value
//
// Empty parameters between semicolons are tolerated.
func parseIssueValue(raw string) (issueValue, error) {
	var v issueValue
	head, rest, hasParams := strings.Cut(raw, ";")
	head = trimWSP(head)
	if head != "" {
		if !isDomain(head) {
			return v, fmt.Errorf("%w: issuer domain %q", errMalformed, head)
		}
		v.issuer = strings.ToLower(head)
	}
	if !hasParams {
		return v, nil
	}
	for _, p := range strings.Split(rest, ";") {
		p = trimWSP(p)
		if p == "" {
			continue
		}
		tag, val, ok := strings.Cut(p, "=")
		tag, val = trimWSP(tag), trimWSP(val)
		if !ok || !isLDH(tag) || !isParamValue(val) {
			return v, fmt.Errorf("%w: parameter %q", errMalformed, p)
		}
		switch {
		case tag == "accounturi":
			v.accountURIs = append(v.accountURIs, val)
		case strings.EqualFold(tag, "accounturi"):
			v.badAccountTag = true
		}
	}
	return v, nil
}

func trimWSP(s string) string { return strings.Trim(s, " \t") }

func isDomain(s string) bool {
	for _, l := range strings.Split(s, ".") {
		if !isLDH(l) {
			return false
		}
	}
	return true
}

// isLDH: (ALPHA / DIGIT) *( *("-") (ALPHA / DIGIT) ).
func isLDH(s string) bool {
	if s == "" || s[0] == '-' || s[len(s)-1] == '-' {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-') {
			return false
		}
	}
	return true
}

// isParamValue: *(%x21-3A / %x3C-7E).
func isParamValue(s string) bool {
	for i := 0; i < len(s); i++ {
		if c := s[i]; c < 0x21 || c > 0x7e || c == ';' {
			return false
		}
	}
	return true
}
