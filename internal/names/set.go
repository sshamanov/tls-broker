package names

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"slices"
	"strings"
)

// ErrEmptySet is returned when a Set would have no names.
var ErrEmptySet = errors.New("identifier set is empty")

// Set is a canonical, immutable set of normalized identifiers: the SAN set of
// one certificate. Names are deduplicated and sorted bytewise, so two Sets
// built from the same names in any order, case or spelling are identical and
// have the same Key.
//
// The zero Set is empty and valid to hold, compare and marshal; NewSet never
// returns it without an error. Set values are safe to copy and to share
// between goroutines. Compare with Equal (Set is not comparable with ==).
//
// A Set does not remove names made redundant by a wildcard ("a.example.com"
// next to "*.example.com"); what the client asked for is what is recorded.
type Set struct {
	names []string // normalized, unique, sorted; never mutated after creation
}

// NewSet normalizes, deduplicates and sorts the given names. It returns the
// first normalization error (*Error), or ErrEmptySet when no names are given.
func NewSet(raw ...string) (Set, error) {
	if len(raw) == 0 {
		return Set{}, ErrEmptySet
	}
	out := make([]string, 0, len(raw))
	for _, r := range raw {
		n, err := Normalize(r)
		if err != nil {
			return Set{}, err
		}
		out = append(out, n)
	}
	slices.Sort(out)
	return Set{names: slices.Compact(out)}, nil
}

// MustSet is NewSet for tests and constants; it panics on error.
func MustSet(raw ...string) Set {
	s, err := NewSet(raw...)
	if err != nil {
		panic(err)
	}
	return s
}

// ParseKey rebuilds a Set from the output of Key. The empty key gives the
// zero Set. Names are normalized again, so a hand-written key is accepted as
// long as its names are valid.
func ParseKey(key string) (Set, error) {
	if key == "" {
		return Set{}, nil
	}
	return NewSet(strings.Split(key, ",")...)
}

// Key returns the stable identity of the set: its names joined by ",". Equal
// sets have equal keys and different sets have different keys. It is the value
// stored in databases and used as map key, lineage key and rate-limit bucket
// for "exact identifier set". The zero Set has key "".
func (s Set) Key() string { return strings.Join(s.names, ",") }

// Hash returns the lowercase hex SHA-256 of Key, for places that need a short
// fixed-length identity (file names, log correlation).
func (s Set) Hash() string {
	sum := sha256.Sum256([]byte(s.Key()))
	return hex.EncodeToString(sum[:])
}

// String is Key; it makes a Set print readably.
func (s Set) String() string { return s.Key() }

// Names returns the sorted names. The slice is a copy; callers may modify it.
func (s Set) Names() []string { return slices.Clone(s.names) }

// Len returns the number of names.
func (s Set) Len() int { return len(s.names) }

// IsZero reports whether the set is empty.
func (s Set) IsZero() bool { return len(s.names) == 0 }

// Equal reports whether both sets hold exactly the same names.
func (s Set) Equal(o Set) bool { return slices.Equal(s.names, o.names) }

// Contains reports whether the normalized name is a literal member of the
// set. It does not apply wildcard matching: a set holding "*.example.com"
// does not Contain "a.example.com".
func (s Set) Contains(name string) bool {
	_, ok := slices.BinarySearch(s.names, name)
	return ok
}

// Overlaps reports whether the two sets share at least one literal name.
func (s Set) Overlaps(o Set) bool {
	for _, n := range s.names {
		if o.Contains(n) {
			return true
		}
	}
	return false
}

// HasWildcard reports whether any name is a wildcard.
func (s Set) HasWildcard() bool { return len(s.Wildcards()) > 0 }

// Wildcards returns the wildcard names, sorted ("*.example.com").
func (s Set) Wildcards() []string {
	var out []string
	for _, n := range s.names {
		if IsWildcard(n) {
			out = append(out, n)
		}
	}
	return out
}

// NonWildcards returns the names that are not wildcards, sorted.
func (s Set) NonWildcards() []string {
	var out []string
	for _, n := range s.names {
		if !IsWildcard(n) {
			out = append(out, n)
		}
	}
	return out
}

// ChallengeRecords returns the distinct DNS-01 record names needed to
// validate the set, sorted. "*.example.com" and "example.com" share one.
func (s Set) ChallengeRecords() []string {
	out := make([]string, 0, len(s.names))
	for _, n := range s.names {
		out = append(out, ChallengeRecord(n))
	}
	slices.Sort(out)
	return slices.Compact(out)
}

// RegisteredDomains returns the distinct registered domains of the names,
// sorted. It fails if any name is a public suffix.
func (s Set) RegisteredDomains() ([]string, error) {
	out := make([]string, 0, len(s.names))
	for _, n := range s.names {
		d, err := RegisteredDomain(n)
		if err != nil {
			return nil, err
		}
		out = append(out, d)
	}
	slices.Sort(out)
	return slices.Compact(out), nil
}

// MarshalText encodes the set as its Key.
func (s Set) MarshalText() ([]byte, error) { return []byte(s.Key()), nil }

// UnmarshalText decodes a Key (see ParseKey).
func (s *Set) UnmarshalText(b []byte) error {
	v, err := ParseKey(string(b))
	if err != nil {
		return err
	}
	*s = v
	return nil
}

// MarshalJSON encodes the set as a JSON array of names; the zero Set is [].
func (s Set) MarshalJSON() ([]byte, error) {
	if s.names == nil {
		return []byte("[]"), nil
	}
	return json.Marshal(s.names)
}

// UnmarshalJSON decodes a JSON array of names, normalizing them. An empty
// array or null gives the zero Set.
func (s *Set) UnmarshalJSON(b []byte) error {
	var raw []string
	if err := json.Unmarshal(b, &raw); err != nil {
		return err
	}
	if len(raw) == 0 {
		*s = Set{}
		return nil
	}
	v, err := NewSet(raw...)
	if err != nil {
		return err
	}
	*s = v
	return nil
}
