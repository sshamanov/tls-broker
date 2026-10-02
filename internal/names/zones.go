package names

import (
	"slices"
)

// Zones is the list of managed DNS zones, used to decide whether a name may
// be handled at all and which zone holds its records. It is immutable and
// safe for concurrent use. The zero Zones manages nothing.
type Zones struct {
	zones []string // normalized, unique, longest first then bytewise
}

// NewZones normalizes the zone names ("Example.COM." becomes "example.com").
// Wildcards are rejected; duplicates are merged.
func NewZones(zoneNames ...string) (Zones, error) {
	out := make([]string, 0, len(zoneNames))
	for _, z := range zoneNames {
		n, err := Normalize(z)
		if err != nil {
			return Zones{}, err
		}
		if IsWildcard(n) {
			return Zones{}, &Error{Input: z, Reason: "a zone name cannot be a wildcard"}
		}
		out = append(out, n)
	}
	slices.SortFunc(out, func(a, b string) int {
		if len(a) != len(b) {
			return len(b) - len(a)
		}
		if a < b {
			return -1
		}
		if a > b {
			return 1
		}
		return 0
	})
	return Zones{zones: slices.Compact(out)}, nil
}

// List returns the normalized zone names, longest first.
func (z Zones) List() []string { return slices.Clone(z.zones) }

// Match returns the managed zone that holds the normalized name: the longest
// zone that equals the name or is a suffix of it on a label boundary. For a
// wildcard the base name is matched, so "*.example.com" is in "example.com".
// ok is false when the name is outside every managed zone.
func (z Zones) Match(name string) (zone string, ok bool) {
	for _, c := range z.zones { // longest first
		if InZone(name, c) {
			return c, true
		}
	}
	return "", false
}

// Contains reports whether the normalized name is inside a managed zone.
func (z Zones) Contains(name string) bool {
	_, ok := z.Match(name)
	return ok
}

// FirstOutside returns the first name of the set (in sorted order) that is
// outside every managed zone; ok is false when all names are managed.
func (z Zones) FirstOutside(s Set) (name string, ok bool) {
	for _, n := range s.names {
		if !z.Contains(n) {
			return n, true
		}
	}
	return "", false
}
