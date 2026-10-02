package names

import (
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"
)

func TestNormalizeAccepts(t *testing.T) {
	long63 := strings.Repeat("a", 63)
	tests := []struct{ in, want string }{
		{"example.com", "example.com"},
		{"Example.COM", "example.com"},
		{"example.com.", "example.com"},
		{"FOO.Example.Com.", "foo.example.com"},
		{"*.example.com", "*.example.com"},
		{"*.Example.com.", "*.example.com"},
		{"a-b.example.com", "a-b.example.com"},
		{"1.example.com", "1.example.com"},
		{"123.example.com", "123.example.com"},
		{"münchen.example.com", "xn--mnchen-3ya.example.com"},
		{"MÜNCHEN.example.com", "xn--mnchen-3ya.example.com"},
		{"xn--mnchen-3ya.example.com", "xn--mnchen-3ya.example.com"},
		{"XN--MNCHEN-3YA.example.com", "xn--mnchen-3ya.example.com"},
		{"пример.рф", "xn--e1afmkfd.xn--p1ai"},
		{"*.bücher.example", "*.xn--bcher-kva.example"},
		{long63 + ".example.com", long63 + ".example.com"},
		{"a.b.c.d.e.example.co.uk", "a.b.c.d.e.example.co.uk"},
		{"host.internal", "host.internal"},
	}
	for _, tc := range tests {
		got, err := Normalize(tc.in)
		if err != nil {
			t.Errorf("Normalize(%q) error: %v", tc.in, err)
			continue
		}
		if got != tc.want {
			t.Errorf("Normalize(%q) = %q, want %q", tc.in, got, tc.want)
		}
		again, err := Normalize(got)
		if err != nil || again != got {
			t.Errorf("Normalize not idempotent for %q: %q, %v", got, again, err)
		}
	}
}

func TestNormalizeRejects(t *testing.T) {
	long64 := strings.Repeat("a", 64)
	// 4 labels of 63 plus dots = 255 characters.
	tooLong := strings.Join([]string{strings.Repeat("a", 63), strings.Repeat("b", 63), strings.Repeat("c", 63), strings.Repeat("d", 63)}, ".")
	// 253 characters without the wildcard; the wildcard pushes it over.
	wildTooLong := "*." + strings.Join([]string{strings.Repeat("a", 63), strings.Repeat("b", 63), strings.Repeat("c", 63), strings.Repeat("d", 61)}, ".")
	tests := []string{
		"",
		".",
		"..",
		" ",
		"example.com ",
		" example.com",
		"exa mple.com",
		"example.com\n",
		"localhost",
		"com",
		"*",
		"*.",
		"*.com",
		"example..com",
		".example.com",
		"example.com..",
		"-a.example.com",
		"a-.example.com",
		"a_b.example.com",
		"_acme-challenge.example.com",
		"a!b.example.com",
		"a/b.example.com",
		"a:b.example.com",
		"foo.*.example.com",
		"*.*.example.com",
		"**.example.com",
		"*foo.example.com",
		"foo*.example.com",
		"f*o.example.com",
		"example.*",
		"192.168.1.10",
		"192.168.1.10.",
		"*.168.1.10",
		"10.0.0.1",
		"::1",
		"2001:db8::1",
		"[2001:db8::1]",
		"[192.168.1.1]",
		"1.2.3",
		"example.123",
		long64 + ".example.com",
		tooLong,
		wildTooLong,
		"xn--.example.com",
		"xn--a.example.com",
		"ab--cd.example.com",
		"example.com:443",
		"https://example.com",
		"user@example.com",
	}
	for _, in := range tests {
		got, err := Normalize(in)
		if err == nil {
			t.Errorf("Normalize(%q) = %q, want error", in, got)
			continue
		}
		if !errors.Is(err, ErrInvalid) {
			t.Errorf("Normalize(%q) error %v does not match ErrInvalid", in, err)
		}
		var ne *Error
		if !errors.As(err, &ne) || ne.Input != in || ne.Reason == "" {
			t.Errorf("Normalize(%q) error = %#v, want *Error with input and reason", in, err)
		}
	}
}

func TestMaxLengthBoundary(t *testing.T) {
	// Exactly 253 characters is accepted.
	n := strings.Join([]string{strings.Repeat("a", 63), strings.Repeat("b", 63), strings.Repeat("c", 63), strings.Repeat("d", 61)}, ".")
	if len(n) != 253 {
		t.Fatalf("test name has length %d", len(n))
	}
	if _, err := Normalize(n); err != nil {
		t.Fatalf("253-character name rejected: %v", err)
	}
}

func TestWildcardHelpers(t *testing.T) {
	if !IsWildcard("*.example.com") || IsWildcard("example.com") {
		t.Fatal("IsWildcard wrong")
	}
	if Base("*.example.com") != "example.com" || Base("a.example.com") != "a.example.com" {
		t.Fatal("Base wrong")
	}
	if Wildcard("example.com") != "*.example.com" || Wildcard("*.example.com") != "*.example.com" {
		t.Fatal("Wildcard wrong")
	}
}

func TestChallengeRecord(t *testing.T) {
	tests := []struct{ in, want string }{
		{"example.com", "_acme-challenge.example.com"},
		{"*.example.com", "_acme-challenge.example.com"},
		{"a.b.example.com", "_acme-challenge.a.b.example.com"},
		{"*.b.example.com", "_acme-challenge.b.example.com"},
	}
	for _, tc := range tests {
		if got := ChallengeRecord(tc.in); got != tc.want {
			t.Errorf("ChallengeRecord(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
	if ChallengeRecord("*.example.com") != ChallengeRecord("example.com") {
		t.Error("wildcard and base must share one challenge record")
	}
}

func TestIdentifierFromChallengeRecord(t *testing.T) {
	tests := []struct {
		in   string
		want string
		ok   bool
	}{
		{"_acme-challenge.example.com", "example.com", true},
		{"_ACME-Challenge.Example.com.", "example.com", true},
		{"example.com", "", false},
		{"foo._acme-challenge.example.com", "", false},
	}
	for _, tc := range tests {
		got, ok := IdentifierFromChallengeRecord(tc.in)
		if got != tc.want || ok != tc.ok {
			t.Errorf("IdentifierFromChallengeRecord(%q) = %q, %v; want %q, %v", tc.in, got, ok, tc.want, tc.ok)
		}
	}
}

func TestRegisteredDomain(t *testing.T) {
	tests := []struct {
		in, want string
		wantErr  bool
	}{
		{"example.com", "example.com", false},
		{"a.b.example.com", "example.com", false},
		{"*.example.com", "example.com", false},
		{"a.example.co.uk", "example.co.uk", false},
		{"*.example.co.uk", "example.co.uk", false},
		{"co.uk", "", true},
		{"*.co.uk", "", true},
		{"host.corp.internal", "corp.internal", false},
	}
	for _, tc := range tests {
		got, err := RegisteredDomain(tc.in)
		if (err != nil) != tc.wantErr || got != tc.want {
			t.Errorf("RegisteredDomain(%q) = %q, %v; want %q, err=%v", tc.in, got, err, tc.want, tc.wantErr)
		}
		if err != nil && !errors.Is(err, ErrInvalid) {
			t.Errorf("RegisteredDomain(%q) error does not match ErrInvalid", tc.in)
		}
	}
}

func TestNewSetCanonical(t *testing.T) {
	a, err := NewSet("B.example.com", "a.example.com.", "*.example.com", "b.EXAMPLE.com")
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"*.example.com", "a.example.com", "b.example.com"}
	if got := a.Names(); !reflect.DeepEqual(got, want) {
		t.Fatalf("Names() = %v, want %v", got, want)
	}
	if a.Key() != "*.example.com,a.example.com,b.example.com" {
		t.Fatalf("Key() = %q", a.Key())
	}
	if a.String() != a.Key() {
		t.Fatal("String() must equal Key()")
	}
	b := MustSet("a.example.com", "b.example.com", "*.example.com")
	if !a.Equal(b) || a.Key() != b.Key() || a.Hash() != b.Hash() {
		t.Fatal("sets built in different order must be identical")
	}
	if len(a.Hash()) != 64 {
		t.Fatalf("Hash() length = %d", len(a.Hash()))
	}
	c := MustSet("a.example.com")
	if a.Equal(c) || a.Key() == c.Key() || a.Hash() == c.Hash() {
		t.Fatal("different sets must differ")
	}
	if a.Len() != 3 || a.IsZero() {
		t.Fatal("Len/IsZero wrong")
	}
}

func TestNewSetErrors(t *testing.T) {
	if _, err := NewSet(); !errors.Is(err, ErrEmptySet) {
		t.Fatalf("NewSet() error = %v, want ErrEmptySet", err)
	}
	if _, err := NewSet("ok.example.com", "bad_name.example.com"); !errors.Is(err, ErrInvalid) {
		t.Fatalf("NewSet with a bad name: error = %v, want ErrInvalid", err)
	}
	defer func() {
		if recover() == nil {
			t.Fatal("MustSet did not panic")
		}
	}()
	MustSet("192.168.0.1")
}

func TestSetNamesIsACopy(t *testing.T) {
	s := MustSet("a.example.com", "b.example.com")
	n := s.Names()
	n[0] = "changed"
	if s.Names()[0] != "a.example.com" {
		t.Fatal("modifying Names() result changed the set")
	}
}

func TestSetMembership(t *testing.T) {
	s := MustSet("*.example.com", "a.example.com", "example.org")
	if !s.Contains("a.example.com") || !s.Contains("*.example.com") {
		t.Fatal("Contains misses a member")
	}
	if s.Contains("b.example.com") {
		t.Fatal("Contains must not apply wildcard matching")
	}
	if !s.HasWildcard() || MustSet("a.example.com").HasWildcard() {
		t.Fatal("HasWildcard wrong")
	}
	if got := s.Wildcards(); !reflect.DeepEqual(got, []string{"*.example.com"}) {
		t.Fatalf("Wildcards() = %v", got)
	}
	if got := s.NonWildcards(); !reflect.DeepEqual(got, []string{"a.example.com", "example.org"}) {
		t.Fatalf("NonWildcards() = %v", got)
	}
	if !s.Overlaps(MustSet("example.org", "x.example.net")) {
		t.Fatal("Overlaps misses a shared name")
	}
	if s.Overlaps(MustSet("b.example.com")) {
		t.Fatal("Overlaps reports a name that is not shared")
	}
	if s.Overlaps(Set{}) || (Set{}).Overlaps(s) {
		t.Fatal("zero set overlaps nothing")
	}
}

func TestSetChallengeRecordsAndDomains(t *testing.T) {
	s := MustSet("*.example.com", "example.com", "a.example.com", "b.example.co.uk")
	wantRec := []string{"_acme-challenge.a.example.com", "_acme-challenge.b.example.co.uk", "_acme-challenge.example.com"}
	if got := s.ChallengeRecords(); !reflect.DeepEqual(got, wantRec) {
		t.Fatalf("ChallengeRecords() = %v, want %v", got, wantRec)
	}
	got, err := s.RegisteredDomains()
	if err != nil || !reflect.DeepEqual(got, []string{"example.co.uk", "example.com"}) {
		t.Fatalf("RegisteredDomains() = %v, %v", got, err)
	}
}

func TestZeroSet(t *testing.T) {
	var z Set
	if !z.IsZero() || z.Len() != 0 || z.Key() != "" || len(z.Names()) != 0 || z.HasWildcard() {
		t.Fatal("zero Set is not empty")
	}
	if !z.Equal(Set{}) {
		t.Fatal("zero sets must be equal")
	}
	b, err := json.Marshal(z)
	if err != nil || string(b) != "[]" {
		t.Fatalf("zero Set JSON = %s, %v", b, err)
	}
	p, err := ParseKey("")
	if err != nil || !p.IsZero() {
		t.Fatalf("ParseKey(\"\") = %v, %v", p, err)
	}
}

func TestSetKeyRoundTrip(t *testing.T) {
	s := MustSet("b.example.com", "*.example.com", "xn--mnchen-3ya.example.com")
	p, err := ParseKey(s.Key())
	if err != nil || !p.Equal(s) {
		t.Fatalf("ParseKey(Key()) = %v, %v", p, err)
	}
	// A hand-written key is normalized.
	p, err = ParseKey("B.example.com,a.example.com,b.example.com")
	if err != nil || p.Key() != "a.example.com,b.example.com" {
		t.Fatalf("ParseKey = %q, %v", p.Key(), err)
	}
	if _, err := ParseKey("a.example.com,,b.example.com"); !errors.Is(err, ErrInvalid) {
		t.Fatalf("ParseKey with empty element: %v", err)
	}
}

func TestSetTextAndJSON(t *testing.T) {
	type wrap struct {
		Names Set            `json:"names"`
		ByKey map[string]int `json:"by_key"`
	}
	s := MustSet("b.example.com", "a.example.com")

	txt, err := s.MarshalText()
	if err != nil || string(txt) != "a.example.com,b.example.com" {
		t.Fatalf("MarshalText = %q, %v", txt, err)
	}
	var fromText Set
	if err := fromText.UnmarshalText(txt); err != nil || !fromText.Equal(s) {
		t.Fatalf("UnmarshalText: %v, %v", fromText, err)
	}
	if err := fromText.UnmarshalText([]byte("bad name")); err == nil {
		t.Fatal("UnmarshalText accepted a bad name")
	}

	b, err := json.Marshal(wrap{Names: s})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), `"names":["a.example.com","b.example.com"]`) {
		t.Fatalf("JSON = %s", b)
	}
	var w wrap
	if err := json.Unmarshal([]byte(`{"names":["B.Example.com","a.example.com","a.example.com."]}`), &w); err != nil {
		t.Fatal(err)
	}
	if !w.Names.Equal(s) {
		t.Fatalf("JSON decode = %v", w.Names)
	}
	if err := json.Unmarshal([]byte(`{"names":null}`), &w); err != nil || !w.Names.IsZero() {
		t.Fatalf("null decode: %v, %v", w.Names, err)
	}
	if err := json.Unmarshal([]byte(`{"names":["10.0.0.1"]}`), &w); !errors.Is(err, ErrInvalid) {
		t.Fatalf("JSON decode of an IP: %v", err)
	}
	if err := json.Unmarshal([]byte(`{"names":"a.example.com"}`), &w); err == nil {
		t.Fatal("JSON decode of a string instead of an array must fail")
	}
}

func TestZonesMatch(t *testing.T) {
	z, err := NewZones("Example.com.", "corp.example.com", "example.org", "example.com")
	if err != nil {
		t.Fatal(err)
	}
	if got := z.List(); !reflect.DeepEqual(got, []string{"corp.example.com", "example.com", "example.org"}) {
		t.Fatalf("List() = %v", got)
	}
	tests := []struct {
		name string
		zone string
		ok   bool
	}{
		{"example.com", "example.com", true},
		{"a.example.com", "example.com", true},
		{"*.example.com", "example.com", true},
		{"corp.example.com", "corp.example.com", true},
		{"a.corp.example.com", "corp.example.com", true},
		{"*.corp.example.com", "corp.example.com", true},
		{"a.b.corp.example.com", "corp.example.com", true},
		{"xcorp.example.com", "example.com", true},
		{"example.org", "example.org", true},
		{"notexample.com", "", false},
		{"badexample.org", "", false},
		{"example.com.evil.net", "", false},
		{"*.example.net", "", false},
		{"com", "", false},
	}
	for _, tc := range tests {
		zone, ok := z.Match(tc.name)
		if zone != tc.zone || ok != tc.ok {
			t.Errorf("Match(%q) = %q, %v; want %q, %v", tc.name, zone, ok, tc.zone, tc.ok)
		}
		if z.Contains(tc.name) != tc.ok {
			t.Errorf("Contains(%q) = %v, want %v", tc.name, !tc.ok, tc.ok)
		}
	}
}

func TestZonesFirstOutside(t *testing.T) {
	z, _ := NewZones("example.com")
	if n, ok := z.FirstOutside(MustSet("a.example.com", "*.example.com")); ok {
		t.Fatalf("FirstOutside reported %q for a managed set", n)
	}
	n, ok := z.FirstOutside(MustSet("a.example.com", "b.example.net", "a.example.net"))
	if !ok || n != "a.example.net" {
		t.Fatalf("FirstOutside = %q, %v; want a.example.net", n, ok)
	}
}

func TestZonesInvalidAndZero(t *testing.T) {
	if _, err := NewZones("*.example.com"); !errors.Is(err, ErrInvalid) {
		t.Fatalf("wildcard zone: %v", err)
	}
	if _, err := NewZones("bad_zone.com"); !errors.Is(err, ErrInvalid) {
		t.Fatalf("bad zone: %v", err)
	}
	var z Zones
	if z.Contains("example.com") || len(z.List()) != 0 {
		t.Fatal("zero Zones must manage nothing")
	}
}

func TestInZone(t *testing.T) {
	if !InZone("a.example.com", "example.com") || !InZone("*.example.com", "example.com") || !InZone("example.com", "example.com") {
		t.Fatal("InZone misses a member")
	}
	if InZone("aexample.com", "example.com") || InZone("example.com", "a.example.com") {
		t.Fatal("InZone accepts a non-member")
	}
}
