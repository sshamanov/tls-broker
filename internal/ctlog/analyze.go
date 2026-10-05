package ctlog

import (
	"cmp"
	"slices"
	"strings"
	"time"

	"tls-broker/internal/core"
	"tls-broker/internal/names"
)

// CAAPolicy is the effective CAA RRset of a managed zone, reduced to the
// issuer domains of its issue and issuewild properties.
type CAAPolicy struct {
	// Node is where the RRset was found (the zone or a parent); "" when
	// there is no CAA anywhere up the tree: every CA may issue.
	Node string
	// Issue and IssueWild are the issuer domains, lower case; an empty
	// string stands for a property that allows no CA (`issue ";"`).
	Issue, IssueWild       []string
	HasIssue, HasIssueWild bool
	// Err is why the lookup failed; the policy is then unknown.
	Err string
}

func newCAAPolicy(node string, rrs []core.CAA) CAAPolicy {
	p := CAAPolicy{Node: node}
	for _, r := range rrs {
		dom, _, _ := strings.Cut(r.Value, ";")
		dom = strings.ToLower(strings.TrimSpace(dom))
		switch strings.ToLower(r.Tag) {
		case "issue":
			p.HasIssue = true
			p.Issue = append(p.Issue, dom)
		case "issuewild":
			p.HasIssueWild = true
			p.IssueWild = append(p.IssueWild, dom)
		}
	}
	return p
}

// Allows says whether a CA with the given CAA issuer domains may issue the
// name (RFC 8659 §4: issuewild governs wildcards when present, else issue;
// without the governing property any CA may issue). known is false when
// the answer cannot be told: the lookup failed or the CA's domains are
// unknown.
func (p CAAPolicy) Allows(caDomains []string, wildcard bool) (allowed, known bool) {
	if p.Err != "" {
		return true, false
	}
	set, has := p.Issue, p.HasIssue
	if wildcard && p.HasIssueWild {
		set, has = p.IssueWild, true
	}
	if p.Node == "" || !has {
		return true, true
	}
	if len(caDomains) == 0 {
		return true, false
	}
	for _, d := range caDomains {
		if d != "" && slices.Contains(set, d) {
			return true, true
		}
	}
	return false, true
}

// Allowed lists the issuer domains the policy allows for a name, for
// messages.
func (p CAAPolicy) Allowed(wildcard bool) []string {
	set := p.Issue
	if wildcard && p.HasIssueWild {
		set = p.IssueWild
	}
	var out []string
	for _, d := range set {
		if d != "" && !slices.Contains(out, d) {
			out = append(out, d)
		}
	}
	return out
}

// knownIssuers maps CA organisations to their CAA issuer domains, for
// issuances whose source gave no caa_domains. Keep it small and explicit.
var knownIssuers = map[string][]string{
	"let's encrypt":         {"letsencrypt.org"},
	"google trust services": {"pki.goog"},
	"sectigo":               {"sectigo.com", "comodoca.com"},
	"zerossl":               {"sectigo.com"},
	"digicert":              {"digicert.com"},
	"buypass":               {"buypass.com"},
	"ssl.com":               {"ssl.com"},
}

// IssuerDomains returns the CAA issuer domains of the issuance's CA: the
// source's caa_domains, else the explicit mapping by organisation.
func (i Issuance) IssuerDomains() []string {
	if len(i.IssuerCAA) > 0 {
		return i.IssuerCAA
	}
	return knownIssuers[strings.ToLower(i.Issuer)]
}

// State is the lifecycle state of an identifier set's current certificate.
type State string

const (
	StateOK       State = "ok"       // valid, before its renewal point
	StateDue      State = "due"      // past the renewal point, no newer certificate yet
	StateOverdue  State = "overdue"  // close to expiry, no newer certificate: a problem
	StateExpired  State = "expired"  // expired, no newer certificate: a problem
	StateReplaced State = "replaced" // past renewal, but every name is in a newer certificate of another set
	StateRevoked  State = "revoked"  // the current certificate is revoked: a problem
)

// RenewPoint is when renewal of a certificate is expected: two thirds of
// its lifetime (30 days before expiry for a 90-day certificate, what
// certbot and Let's Encrypt's ARI suggest).
func RenewPoint(nb, na time.Time) time.Time { return nb.Add(na.Sub(nb) * 2 / 3) }

// UrgentPoint is when a certificate that has not been renewed becomes
// overdue: seven days before expiry, or the last tenth of its lifetime for
// certificates shorter than 70 days.
func UrgentPoint(nb, na time.Time) time.Time { return na.Add(-min(7*24*time.Hour, na.Sub(nb)/10)) }

// Source of a certificate, as far as the broker can tell.
const (
	SourceBroker  = "broker"  // the broker obtained it (ACME proxy or direct)
	SourceOutside = "outside" // someone else did: an ACME client of its own, another system
)

// Cert is an identifier set with its current (newest) certificate.
type Cert struct {
	Issuance
	State   State
	RenewAt time.Time
	UrgeAt  time.Time
	// Zones are the managed zones the names belong to.
	Zones []string
	// UnexpectedCA: the zone's CAA does not allow the issuing CA for at
	// least one name; CAADetail says which and what is allowed.
	UnexpectedCA bool
	CAADetail    string
	Source       string
	// History are the older certificates of the same set, newest first.
	History []Issuance
}

// Problem reports whether the set needs someone's attention.
func (c Cert) Problem() bool {
	switch c.State {
	case StateOverdue, StateExpired, StateRevoked:
		return true
	}
	return c.UnexpectedCA
}

// Recent is one issuance of the recent window.
type Recent struct {
	Issuance
	// Kind is renewal (an older certificate for the same names exists),
	// changed (some names were in an older certificate of another set) or
	// new.
	Kind   string
	Source string
}

// RecentWindow is how far back the recent issuance list goes.
const RecentWindow = 14 * 24 * time.Hour

// Report is the analysed inventory.
type Report struct {
	Certs    []Cert   // by urgency: problems, then due, then by renewal point
	Recent   []Recent // issued within RecentWindow, newest first
	Problems int
	Counts   map[State]int
	// RecentRenewals and RecentNew count Recent by kind (changed counts as new).
	RecentRenewals, RecentNew int
	Unexpected                int
}

// Analyze groups the snapshot's issuances by identifier set and computes
// each set's state at now. broker reports whether the broker issued a
// certificate with the given serial (nil: never).
func Analyze(s Snapshot, now time.Time, broker func(serial string) bool) Report {
	zones, _ := names.NewZones(s.ManagedZones...)
	source := func(is Issuance) string {
		if broker != nil && is.Serial != "" && broker(is.Serial) {
			return SourceBroker
		}
		return SourceOutside
	}
	sets := map[string][]Issuance{}
	for _, is := range s.Issuances {
		sets[is.Key()] = append(sets[is.Key()], is)
	}
	newest := func(list []Issuance) {
		slices.SortFunc(list, func(a, b Issuance) int {
			if c := b.NotBefore.Compare(a.NotBefore); c != 0 {
				return c
			}
			if c := b.NotAfter.Compare(a.NotAfter); c != 0 {
				return c
			}
			return strings.Compare(b.ID, a.ID)
		})
	}
	// covered: a name is in a valid certificate of another set issued
	// after t.
	covered := func(name, key string, after time.Time) bool {
		for _, is := range s.Issuances {
			if is.Key() != key && !is.Revoked && is.NotBefore.After(after) && is.NotAfter.After(now) && slices.Contains(is.Names, name) {
				return true
			}
		}
		return false
	}

	r := Report{Counts: map[State]int{}}
	for key, list := range sets {
		newest(list)
		cur := list[0]
		c := Cert{Issuance: cur, History: slices.Clone(list[1:]), Source: source(cur),
			RenewAt: RenewPoint(cur.NotBefore, cur.NotAfter), UrgeAt: UrgentPoint(cur.NotBefore, cur.NotAfter)}
		switch {
		case cur.Revoked:
			c.State = StateRevoked
		case !now.Before(cur.NotAfter):
			c.State = StateExpired
		case !now.Before(c.UrgeAt):
			c.State = StateOverdue
		case !now.Before(c.RenewAt):
			c.State = StateDue
		default:
			c.State = StateOK
		}
		if c.State == StateDue || c.State == StateOverdue || c.State == StateExpired {
			all := true
			for _, n := range cur.Names {
				if !covered(n, key, cur.NotBefore) {
					all = false
					break
				}
			}
			if all {
				c.State = StateReplaced
			}
		}
		var bad []string
		for _, n := range cur.Names {
			z, ok := zones.Match(names.Base(n))
			if !ok {
				continue
			}
			if !slices.Contains(c.Zones, z) {
				c.Zones = append(c.Zones, z)
			}
			pol := s.CAA[z]
			if allowed, known := pol.Allows(cur.IssuerDomains(), names.IsWildcard(n)); known && !allowed {
				bad = append(bad, n)
				if c.CAADetail == "" {
					c.CAADetail = caaDetail(cur, z, pol, names.IsWildcard(n))
				}
			}
		}
		slices.Sort(c.Zones)
		// A replaced certificate is out of use; its CA no longer matters.
		c.UnexpectedCA = len(bad) > 0 && c.State != StateReplaced
		r.Counts[c.State]++
		if c.UnexpectedCA {
			r.Unexpected++
		}
		if c.Problem() {
			r.Problems++
		}
		r.Certs = append(r.Certs, c)
	}
	slices.SortFunc(r.Certs, func(a, b Cert) int {
		if c := cmp.Compare(urgency(a), urgency(b)); c != 0 {
			return c
		}
		at, bt := a.NotAfter, b.NotAfter
		if urgency(a) >= 3 {
			at, bt = a.RenewAt, b.RenewAt
		}
		if c := at.Compare(bt); c != 0 {
			return c
		}
		return strings.Compare(a.Key(), b.Key())
	})

	since := now.Add(-RecentWindow)
	for _, is := range s.Issuances {
		if is.NotBefore.Before(since) || is.NotBefore.After(now) {
			continue
		}
		rc := Recent{Issuance: is, Kind: "new", Source: source(is)}
		for _, o := range s.Issuances {
			if o.TBSSHA256 == is.TBSSHA256 || !o.NotBefore.Before(is.NotBefore) {
				continue
			}
			if o.Key() == is.Key() {
				rc.Kind = "renewal"
				break
			}
			for _, n := range is.Names {
				if slices.Contains(o.Names, n) {
					rc.Kind = "changed"
				}
			}
		}
		if rc.Kind == "renewal" {
			r.RecentRenewals++
		} else {
			r.RecentNew++
		}
		r.Recent = append(r.Recent, rc)
	}
	slices.SortFunc(r.Recent, func(a, b Recent) int {
		if c := b.NotBefore.Compare(a.NotBefore); c != 0 {
			return c
		}
		return strings.Compare(b.ID, a.ID)
	})
	return r
}

// urgency orders states for the list: 0 expired, 1 revoked or overdue,
// 2 an unexpected CA, 3 due, 4 ok, 5 replaced.
func urgency(c Cert) int {
	switch c.State {
	case StateExpired:
		return 0
	case StateRevoked, StateOverdue:
		return 1
	}
	if c.UnexpectedCA {
		return 2
	}
	switch c.State {
	case StateDue:
		return 3
	case StateOK:
		return 4
	}
	return 5
}

func caaDetail(is Issuance, zone string, p CAAPolicy, wildcard bool) string {
	ca := is.Issuer
	if ca == "" {
		ca = is.IssuerDN
	}
	tag := "issue"
	if wildcard && p.HasIssueWild {
		tag = "issuewild"
	}
	allowed := p.Allowed(wildcard)
	msg := ca + " is not allowed by the CAA " + tag + " records of " + zone
	if len(allowed) == 0 {
		return msg + " (no CA is)"
	}
	return msg + " (allowed: " + strings.Join(allowed, ", ") + ")"
}
