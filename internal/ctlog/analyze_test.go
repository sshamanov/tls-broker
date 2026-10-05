package ctlog

import (
	"strings"
	"testing"
	"time"

	"tls-broker/internal/core"
)

func snap(list ...Issuance) Snapshot {
	return Snapshot{Enabled: true, ManagedZones: []string{"example.com", "example.org"}, CAA: map[string]CAAPolicy{}, Issuances: list}
}

func certFor(t *testing.T, r Report, key string) Cert {
	t.Helper()
	for _, c := range r.Certs {
		if c.Key() == key {
			return c
		}
	}
	t.Fatalf("no set %s in %+v", key, r.Certs)
	return Cert{}
}

// The state rules at their boundaries, for a 90-day and a 6-day
// certificate: renewal due at two thirds of the lifetime, overdue seven
// days (or the last tenth) before expiry, expired at NotAfter.
func TestStatesAtBoundaries(t *testing.T) {
	const life = 90 * day
	cases := []struct {
		age  time.Duration
		life time.Duration
		want State
	}{
		{60*day - time.Second, life, StateOK},
		{60 * day, life, StateDue},
		{83*day - time.Second, life, StateDue},
		{83 * day, life, StateOverdue},
		{90*day - time.Second, life, StateOverdue},
		{90 * day, life, StateExpired},
		{4 * day, 6 * day, StateDue},
		{6*day - 14*time.Hour - 24*time.Minute, 6 * day, StateOverdue}, // last tenth = 14h24m
	}
	for _, tc := range cases {
		r := Analyze(snap(aged(iss("x", "a.example.com"), tc.age, tc.life)), t0, nil)
		if got := r.Certs[0].State; got != tc.want {
			t.Errorf("age %s of %s: %s, want %s", tc.age, tc.life, got, tc.want)
		}
	}
	if got := RenewPoint(t0, t0.Add(90*day)); !got.Equal(t0.Add(60 * day)) {
		t.Fatalf("renew point %s", got)
	}
	revoked := iss("r", "a.example.com")
	revoked.Revoked = true
	if r := Analyze(snap(revoked), t0, nil); r.Certs[0].State != StateRevoked || r.Problems != 1 {
		t.Fatalf("revoked: %+v", r.Certs[0])
	}
}

func TestNewestIsCurrentAndHistoryKept(t *testing.T) {
	old := aged(iss("old", "a.example.com"), 70*day, 90*day)
	cur := aged(iss("cur", "a.example.com"), 10*day, 90*day)
	r := Analyze(snap(old, cur), t0, nil)
	if len(r.Certs) != 1 {
		t.Fatalf("sets %d", len(r.Certs))
	}
	c := r.Certs[0]
	if c.TBSSHA256 != "cur" || c.State != StateOK || len(c.History) != 1 || c.History[0].TBSSHA256 != "old" || r.Problems != 0 {
		t.Fatalf("cert %+v", c)
	}
}

// A set whose names all moved into a newer certificate of another set is
// replaced, not overdue or expired.
func TestReplacedByAnotherSet(t *testing.T) {
	single := aged(iss("s", "a.example.com"), 89*day, 90*day)
	merged := aged(iss("m", "a.example.com", "b.example.com"), 20*day, 90*day)
	partial := aged(iss("p", "c.example.com", "d.example.com"), 89*day, 90*day)
	onlyC := aged(iss("c", "c.example.com"), 5*day, 90*day)
	r := Analyze(snap(single, merged, partial, onlyC), t0, nil)
	if c := certFor(t, r, "a.example.com"); c.State != StateReplaced || c.Problem() {
		t.Fatalf("single %+v", c)
	}
	if c := certFor(t, r, "c.example.com,d.example.com"); c.State != StateOverdue {
		t.Fatalf("d.example.com is in no newer certificate: %+v", c)
	}
	if r.Problems != 1 || r.Certs[len(r.Certs)-1].State != StateReplaced {
		t.Fatalf("problems %d, order %+v", r.Problems, r.Certs)
	}
}

func TestUnexpectedCA(t *testing.T) {
	s := snap()
	s.CAA["example.com"] = newCAAPolicy("example.com", []core.CAA{
		{Tag: "issue", Value: "letsencrypt.org"}, {Tag: "issue", Value: "pki.goog"},
		{Tag: "issuewild", Value: "letsencrypt.org; accounturi=https://acme.test/acct/1"},
	})
	s.CAA["example.org"] = CAAPolicy{Err: "resolver failed"}
	google := func(tbs string, names ...string) Issuance {
		is := iss(tbs, names...)
		is.Issuer, is.IssuerCAA = "Google Trust Services", []string{"pki.goog"}
		return is
	}
	other := iss("o", "other.example.com")
	other.Issuer, other.IssuerCAA = "Sectigo Limited", []string{"sectigo.com"}
	mapped := iss("mapped", "mapped.example.com")
	mapped.Issuer, mapped.IssuerCAA = "Sectigo", nil
	unknown := iss("u", "unknown.example.com")
	unknown.Issuer, unknown.IssuerCAA = "Some New CA", nil
	s.Issuances = []Issuance{google("g", "www.example.com"), google("w", "*.example.com"), other, mapped, unknown,
		google("org", "www.example.org")}
	r := Analyze(s, t0, nil)
	if c := certFor(t, r, "www.example.com"); c.UnexpectedCA {
		t.Fatalf("issue allows pki.goog: %+v", c)
	}
	w := certFor(t, r, "*.example.com")
	if !w.UnexpectedCA || !w.Problem() || !strings.Contains(w.CAADetail, "issuewild") || !strings.Contains(w.CAADetail, "allowed: letsencrypt.org") {
		t.Fatalf("issuewild pins Let's Encrypt: %+v", w)
	}
	if c := certFor(t, r, "other.example.com"); !c.UnexpectedCA {
		t.Fatalf("sectigo.com not in issue: %+v", c)
	}
	if c := certFor(t, r, "mapped.example.com"); !c.UnexpectedCA {
		t.Fatalf("organisation mapping: %+v", c)
	}
	if c := certFor(t, r, "unknown.example.com"); c.UnexpectedCA {
		t.Fatalf("an unknown CA cannot be judged: %+v", c)
	}
	if c := certFor(t, r, "www.example.org"); c.UnexpectedCA {
		t.Fatalf("failed CAA lookup cannot be judged: %+v", c)
	}
	if r.Unexpected != 3 || r.Problems != 3 || !r.Certs[0].UnexpectedCA {
		t.Fatalf("unexpected %d problems %d first %s", r.Unexpected, r.Problems, r.Certs[0].Key())
	}

	none := snap(google("n", "a.example.com"))
	if r := Analyze(none, t0, nil); r.Certs[0].UnexpectedCA {
		t.Fatal("without CAA every CA may issue")
	}
	deny := snap(iss("d", "a.example.com"))
	deny.CAA["example.com"] = newCAAPolicy("example.com", []core.CAA{{Tag: "issue", Value: ";"}})
	if r := Analyze(deny, t0, nil); !r.Certs[0].UnexpectedCA || !strings.Contains(r.Certs[0].CAADetail, "no CA is") {
		t.Fatalf(`issue ";" allows nobody: %+v`, r.Certs[0])
	}
}

func TestBrokerSource(t *testing.T) {
	mine := iss("m", "a.example.com")
	mine.Serial = "abc"
	theirs := iss("t", "b.example.com")
	theirs.Serial = "def"
	r := Analyze(snap(mine, theirs), t0, func(serial string) bool { return serial == "abc" })
	if certFor(t, r, "a.example.com").Source != SourceBroker || certFor(t, r, "b.example.com").Source != SourceOutside {
		t.Fatalf("%+v", r.Certs)
	}
	if r.Problems != 0 {
		t.Fatal("outside the broker is not a problem")
	}
}

func TestRecentIssuance(t *testing.T) {
	renewed := aged(iss("r1", "a.example.com"), 70*day, 90*day)
	renewal := aged(iss("r2", "a.example.com"), 2*day, 90*day)
	changedOld := aged(iss("c1", "b.example.com"), 50*day, 90*day)
	changed := aged(iss("c2", "b.example.com", "c.example.com"), 1*day, 90*day)
	fresh := aged(iss("n", "new.example.com"), time.Hour, 90*day)
	tooOld := aged(iss("o", "old.example.com"), 15*day, 90*day)
	r := Analyze(snap(renewed, renewal, changedOld, changed, fresh, tooOld), t0, nil)
	if len(r.Recent) != 3 {
		t.Fatalf("recent %+v", r.Recent)
	}
	got := []string{}
	for _, rc := range r.Recent {
		got = append(got, rc.TBSSHA256+":"+rc.Kind)
	}
	if strings.Join(got, " ") != "n:new c2:changed r2:renewal" || r.RecentRenewals != 1 || r.RecentNew != 2 {
		t.Fatalf("recent %v renewals %d new %d", got, r.RecentRenewals, r.RecentNew)
	}
}

func TestUrgencyOrder(t *testing.T) {
	expired := aged(iss("e", "e.example.com"), 91*day, 90*day)
	overdue := aged(iss("o", "o.example.com"), 85*day, 90*day)
	due := aged(iss("d", "d.example.com"), 65*day, 90*day)
	okSoon := aged(iss("k1", "k1.example.com"), 50*day, 90*day)
	okLate := aged(iss("k2", "k2.example.com"), 5*day, 90*day)
	r := Analyze(snap(okLate, due, okSoon, overdue, expired), t0, nil)
	var got []string
	for _, c := range r.Certs {
		got = append(got, c.TBSSHA256)
	}
	if strings.Join(got, ",") != "e,o,d,k1,k2" || r.Problems != 2 || r.Counts[StateOK] != 2 {
		t.Fatalf("order %v problems %d counts %v", got, r.Problems, r.Counts)
	}
	if c := certFor(t, r, "e.example.com"); len(c.Zones) != 1 || c.Zones[0] != "example.com" {
		t.Fatalf("zones %v", c.Zones)
	}
}
