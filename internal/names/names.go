// Package names normalizes DNS identifiers and gives them a stable identity.
//
// Every identifier is normalized here before it reaches policy, the cache,
// rate accounting, audit or an upstream CA (architecture §18). The canonical
// form of a name is:
//
//   - ASCII lowercase, internationalized labels in punycode ("xn--...");
//   - no trailing dot;
//   - at least two labels, each 1..63 characters of [a-z0-9-], not starting or
//     ending with a hyphen; at most 253 characters in total;
//   - optionally one wildcard, only as the leading label ("*.example.com").
//
// IP address literals are rejected. Membership in a managed zone is a separate
// question answered by Zones.
package names

import (
	"errors"
	"fmt"
	"net/netip"
	"strings"

	"golang.org/x/net/idna"
	"golang.org/x/net/publicsuffix"
)

// ErrInvalid is matched (errors.Is) by every normalization error.
var ErrInvalid = errors.New("invalid identifier")

// Error describes why an identifier was rejected. It matches ErrInvalid.
type Error struct {
	Input  string // the name as given
	Reason string // short, human readable, safe to show to a client
}

func (e *Error) Error() string {
	return fmt.Sprintf("invalid identifier %q: %s", e.Input, e.Reason)
}

// Is reports whether target is ErrInvalid.
func (e *Error) Is(target error) bool { return target == ErrInvalid }

const (
	wildcardPrefix  = "*."
	challengePrefix = "_acme-challenge."
	maxNameLen      = 253
	maxLabelLen     = 63
)

var profile = idna.New(
	idna.MapForLookup(),
	idna.BidiRule(),
	idna.StrictDomainName(true),
	idna.CheckHyphens(true),
)

// Normalize returns the canonical form of a DNS identifier, or an *Error.
//
// It accepts mixed case, one trailing dot, Unicode labels (converted to
// punycode) and a leading "*." wildcard label. It rejects empty names,
// whitespace, IP literals (IPv4, IPv6, bracketed), single-label names, names
// whose last label is all digits, malformed labels, and a "*" anywhere except
// as the whole first label. Normalize is idempotent.
func Normalize(raw string) (string, error) {
	bad := func(reason string) (string, error) {
		return "", &Error{Input: raw, Reason: reason}
	}
	s := raw
	if s == "" {
		return bad("empty name")
	}
	if strings.ContainsAny(s, " \t\r\n") {
		return bad("contains whitespace")
	}
	if isIPLiteral(s) {
		return bad("IP address literals are not allowed")
	}
	s = strings.TrimSuffix(s, ".")
	if s == "" {
		return bad("empty name")
	}
	wild := false
	if strings.HasPrefix(s, wildcardPrefix) {
		wild = true
		s = s[len(wildcardPrefix):]
	}
	if strings.Contains(s, "*") {
		return bad("wildcard is only allowed as the leading label")
	}
	if s == "" {
		return bad("empty name")
	}
	if strings.HasPrefix(s, ".") || strings.HasSuffix(s, ".") || strings.Contains(s, "..") {
		return bad("empty label")
	}
	ascii, err := profile.ToASCII(s)
	if err != nil {
		return bad("malformed label")
	}
	s = ascii
	labels := strings.Split(s, ".")
	if len(labels) < 2 {
		return bad("needs at least two labels")
	}
	for _, l := range labels {
		if reason := checkLabel(l); reason != "" {
			return bad(reason)
		}
	}
	if allDigits(labels[len(labels)-1]) {
		return bad("last label must not be numeric")
	}
	if wild {
		s = wildcardPrefix + s
	}
	if len(s) > maxNameLen {
		return bad("name too long")
	}
	return s, nil
}

func isIPLiteral(s string) bool {
	t := strings.TrimSuffix(s, ".")
	t = strings.TrimPrefix(t, wildcardPrefix)
	if strings.HasPrefix(t, "[") && strings.HasSuffix(t, "]") {
		return true
	}
	_, err := netip.ParseAddr(t)
	return err == nil
}

func checkLabel(l string) string {
	if l == "" {
		return "empty label"
	}
	if len(l) > maxLabelLen {
		return "label too long"
	}
	if l[0] == '-' || l[len(l)-1] == '-' {
		return "label starts or ends with a hyphen"
	}
	for i := 0; i < len(l); i++ {
		c := l[i]
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
			return "label contains a character outside a-z, 0-9, hyphen"
		}
	}
	return ""
}

func allDigits(l string) bool {
	for i := 0; i < len(l); i++ {
		if l[i] < '0' || l[i] > '9' {
			return false
		}
	}
	return l != ""
}

// IsWildcard reports whether a normalized name is a wildcard ("*.example.com").
func IsWildcard(name string) bool { return strings.HasPrefix(name, wildcardPrefix) }

// Base returns a normalized name without its wildcard label:
// Base("*.example.com") == "example.com", Base("a.example.com") is unchanged.
func Base(name string) string { return strings.TrimPrefix(name, wildcardPrefix) }

// Wildcard returns the wildcard name covering the direct children of a
// normalized base name: Wildcard("example.com") == "*.example.com". A name
// that is already a wildcard is returned unchanged.
func Wildcard(base string) string {
	if IsWildcard(base) {
		return base
	}
	return wildcardPrefix + base
}

// ChallengeRecord returns the DNS-01 TXT record name for a normalized
// identifier, without a trailing dot. A wildcard and its base name share one
// record: both "*.example.com" and "example.com" give
// "_acme-challenge.example.com".
func ChallengeRecord(name string) string { return challengePrefix + Base(name) }

// IdentifierFromChallengeRecord is the inverse of ChallengeRecord: it strips
// the "_acme-challenge." label and returns the (non-wildcard) name the record
// validates. ok is false when record does not start with that label. A
// trailing dot and letter case in record are tolerated.
func IdentifierFromChallengeRecord(record string) (name string, ok bool) {
	r := strings.ToLower(strings.TrimSuffix(record, "."))
	if !strings.HasPrefix(r, challengePrefix) {
		return "", false
	}
	return r[len(challengePrefix):], true
}

// RegisteredDomain returns the registrable domain (public suffix plus one
// label) of a normalized name, which is the unit CAs use for per-domain rate
// limits: "a.b.example.co.uk" and "*.example.co.uk" give "example.co.uk". It
// fails when the name is itself a public suffix.
func RegisteredDomain(name string) (string, error) {
	d, err := publicsuffix.EffectiveTLDPlusOne(Base(name))
	if err != nil {
		return "", &Error{Input: name, Reason: "no registered domain (name is a public suffix)"}
	}
	return d, nil
}

// InZone reports whether a normalized name (wildcard or not) lies in the
// normalized zone: equal to it or below it on a label boundary.
func InZone(name, zone string) bool {
	b := Base(name)
	return b == zone || strings.HasSuffix(b, "."+zone)
}
