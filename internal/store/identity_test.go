package store

import (
	"net/netip"
	"reflect"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"tls-broker/internal/core"
)

func TestUsers(t *testing.T) {
	s := open(t)
	us := s.Users()

	u, created, err := us.Ensure(ctx, "bob", false, t0)
	must(t, err)
	if !created || u.ID == 0 || u.Role != core.RoleNormal || u.Blocked || u.Local || !u.CreatedAt.Equal(t0) || !u.LastLoginAt.IsZero() {
		t.Fatalf("Ensure created %+v (created=%v)", u, created)
	}
	again, created, err := us.Ensure(ctx, "bob", false, t0.Add(time.Hour))
	must(t, err)
	if created || again.ID != u.ID || !again.CreatedAt.Equal(t0) {
		t.Fatalf("second Ensure: %+v created=%v", again, created)
	}
	local, created, err := us.Ensure(ctx, "bob", true, t0)
	must(t, err)
	if !created || local.ID == u.ID || !local.Local {
		t.Fatalf("local user of same name: %+v", local)
	}
	_, _, err = us.Ensure(ctx, "alice", false, t0)
	must(t, err)

	list, err := us.List(ctx)
	must(t, err)
	var got []string
	for _, x := range list {
		got = append(got, x.Username+map[bool]string{true: "/local", false: ""}[x.Local])
	}
	if want := []string{"alice", "bob", "bob/local"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("List order %v, want %v", got, want)
	}

	must(t, us.SetRole(ctx, u.ID, core.RoleWildcardAllowed))
	must(t, us.SetBlocked(ctx, u.ID, true))
	must(t, us.TouchLogin(ctx, u.ID, t0.Add(2*time.Hour)))
	u2, err := us.GetByUsername(ctx, "bob", false)
	must(t, err)
	if u2.Role != core.RoleWildcardAllowed || !u2.Blocked || !u2.LastLoginAt.Equal(t0.Add(2*time.Hour)) {
		t.Fatalf("after updates: %+v", u2)
	}
	must(t, us.SetBlocked(ctx, u.ID, false))
	u3, _ := us.Get(ctx, u.ID)
	if u3.Blocked {
		t.Fatal("unblock did not stick")
	}

	if err := us.SetRole(ctx, u.ID, "root"); err == nil {
		t.Fatal("invalid role accepted")
	}
	_, err = us.Get(ctx, 9999)
	wantErr(t, err, core.ErrNotFound)
	_, err = us.GetByUsername(ctx, "nobody", false)
	wantErr(t, err, core.ErrNotFound)
	wantErr(t, us.SetRole(ctx, 9999, core.RoleAdmin), core.ErrNotFound)
	wantErr(t, us.SetBlocked(ctx, 9999, true), core.ErrNotFound)
	wantErr(t, us.TouchLogin(ctx, 9999, t0), core.ErrNotFound)
}

func TestUsersEnsureConcurrent(t *testing.T) {
	s := open(t)
	var wg sync.WaitGroup
	var creations atomic.Int32
	ids := make([]int64, 20)
	for i := range ids {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			u, created, err := s.Users().Ensure(ctx, "carol", false, t0)
			if err != nil {
				t.Error(err)
				return
			}
			if created {
				creations.Add(1)
			}
			ids[i] = u.ID
		}(i)
	}
	wg.Wait()
	if creations.Load() != 1 {
		t.Fatalf("%d creations, want 1", creations.Load())
	}
	for _, id := range ids {
		if id != ids[0] {
			t.Fatalf("different IDs returned: %v", ids)
		}
	}
}

func TestGrants(t *testing.T) {
	s := open(t)
	gs := s.Grants()
	mk := func(prefix string, enabled, wildcard bool, owner int64) *core.Grant {
		g := &core.Grant{OwnerUserID: owner, Prefix: netip.MustParsePrefix(prefix), Enabled: enabled, Wildcard: wildcard,
			Note: "n " + prefix, CreatedAt: t0}
		must(t, gs.Create(ctx, g))
		if g.ID == 0 {
			t.Fatal("ID not set")
		}
		return g
	}
	wide := mk("10.1.2.3/8", true, false, 1) // stored masked
	if wide.Prefix.String() != "10.0.0.0/8" {
		t.Fatalf("prefix not masked: %s", wide.Prefix)
	}
	host := mk("10.1.2.3/32", true, false, 2)
	mid := mk("10.1.0.0/16", true, false, 1)
	wild := mk("10.0.0.0/8", true, true, 2)
	disabled := mk("10.1.2.0/24", false, true, 1)
	all := mk("0.0.0.0/0", true, false, 3)
	other := mk("192.168.1.0/24", true, false, 3)

	ids := func(list []core.Grant) []int64 {
		out := []int64{}
		for _, g := range list {
			out = append(out, g.ID)
		}
		return out
	}
	m, err := gs.Match(ctx, netip.MustParseAddr("10.1.2.3"))
	must(t, err)
	if want := []int64{wild.ID, host.ID, mid.ID, wide.ID, all.ID}; !reflect.DeepEqual(ids(m), want) {
		t.Fatalf("Match order %v, want %v", ids(m), want)
	}
	m, _ = gs.Match(ctx, netip.MustParseAddr("10.1.2.4"))
	if want := []int64{wild.ID, mid.ID, wide.ID, all.ID}; !reflect.DeepEqual(ids(m), want) {
		t.Fatalf("Match neighbour %v, want %v", ids(m), want)
	}
	// Prefix boundaries.
	m, _ = gs.Match(ctx, netip.MustParseAddr("192.168.1.255"))
	if want := []int64{other.ID, all.ID}; !reflect.DeepEqual(ids(m), want) {
		t.Fatalf("Match last address %v", ids(m))
	}
	m, _ = gs.Match(ctx, netip.MustParseAddr("192.168.2.0"))
	if want := []int64{all.ID}; !reflect.DeepEqual(ids(m), want) {
		t.Fatalf("Match outside %v", ids(m))
	}
	m, _ = gs.Match(ctx, netip.MustParseAddr("255.255.255.255"))
	if want := []int64{all.ID}; !reflect.DeepEqual(ids(m), want) {
		t.Fatalf("Match broadcast %v", ids(m))
	}
	for _, a := range []string{"::1", "::ffff:10.1.2.3"} {
		m, err = gs.Match(ctx, netip.MustParseAddr(a))
		must(t, err)
		if len(m) != 0 || m == nil {
			t.Fatalf("non-IPv4 %s matched %v", a, m)
		}
	}
	m, _ = gs.Match(ctx, netip.Addr{})
	if len(m) != 0 {
		t.Fatal("invalid address matched")
	}

	// Update changes the mutable fields only.
	disabled.Enabled, disabled.Note, disabled.OwnerUserID = true, "on", 9
	disabled.Prefix = netip.MustParsePrefix("1.2.3.4/32")
	must(t, gs.Update(ctx, disabled))
	g, err := gs.Get(ctx, disabled.ID)
	must(t, err)
	if !g.Enabled || g.Note != "on" || g.OwnerUserID != 9 || g.Prefix.String() != "10.1.2.0/24" || !g.CreatedAt.Equal(t0) {
		t.Fatalf("after Update: %+v", g)
	}
	m, _ = gs.Match(ctx, netip.MustParseAddr("10.1.2.3"))
	// Wildcard grants first, the longer wildcard prefix before the wider one.
	if want := []int64{disabled.ID, wild.ID, host.ID, mid.ID, wide.ID, all.ID}; !reflect.DeepEqual(ids(m), want) {
		t.Fatalf("Match after enabling: %v, want %v", ids(m), want)
	}

	l, err := gs.List(ctx, 0)
	must(t, err)
	if len(l) != 7 || l[0].ID != wide.ID {
		t.Fatalf("List all: %v", ids(l))
	}
	l, _ = gs.List(ctx, 3)
	if want := []int64{all.ID, other.ID}; !reflect.DeepEqual(ids(l), want) {
		t.Fatalf("List owner 3: %v", ids(l))
	}

	must(t, gs.Delete(ctx, host.ID))
	_, err = gs.Get(ctx, host.ID)
	wantErr(t, err, core.ErrNotFound)
	wantErr(t, gs.Delete(ctx, host.ID), core.ErrNotFound)
	wantErr(t, gs.Update(ctx, &core.Grant{ID: 999}), core.ErrNotFound)

	for _, bad := range []netip.Prefix{{}, netip.MustParsePrefix("2001:db8::/32")} {
		if err := gs.Create(ctx, &core.Grant{Prefix: bad}); err == nil {
			t.Errorf("Create accepted %v", bad)
		}
	}
}

func TestSessions(t *testing.T) {
	s := open(t)
	ss := s.Sessions()
	u, _, err := s.Users().Ensure(ctx, "dave", false, t0)
	must(t, err)
	u2, _, _ := s.Users().Ensure(ctx, "erin", false, t0)
	mk := func(token string, user int64, expires time.Time) *core.Session {
		x := &core.Session{TokenHash: core.HashToken(token), UserID: user, CSRFToken: "csrf-" + token,
			SourceIP: netip.MustParseAddr("10.0.0.9"), CreatedAt: t0, ExpiresAt: expires, LastSeenAt: t0}
		must(t, ss.Create(ctx, x))
		return x
	}
	a := mk("a", u.ID, t0.Add(time.Hour))
	mk("b", u.ID, t0.Add(2*time.Hour))
	mk("c", u2.ID, t0.Add(3*time.Hour))

	got, err := ss.Get(ctx, a.TokenHash)
	must(t, err)
	if !reflect.DeepEqual(got, a) {
		t.Fatalf("Get: %+v, want %+v", got, a)
	}
	wantErr(t, ss.Create(ctx, a), core.ErrConflict)
	wantErr(t, ss.Create(ctx, &core.Session{TokenHash: "zz", UserID: 4242, ExpiresAt: t0}), core.ErrConflict)

	must(t, ss.Touch(ctx, a.TokenHash, t0.Add(time.Minute)))
	got, _ = ss.Get(ctx, a.TokenHash)
	if !got.LastSeenAt.Equal(t0.Add(time.Minute)) {
		t.Fatal("Touch did not stick")
	}
	must(t, ss.Touch(ctx, "missing", t0))
	must(t, ss.Delete(ctx, "missing"))

	// Expiry: ExpiresAt <= now is expired.
	n, err := ss.DeleteExpired(ctx, t0.Add(time.Hour))
	must(t, err)
	if n != 1 {
		t.Fatalf("DeleteExpired removed %d, want 1", n)
	}
	_, err = ss.Get(ctx, a.TokenHash)
	wantErr(t, err, core.ErrNotFound)

	n, err = ss.DeleteByUser(ctx, u.ID)
	must(t, err)
	if n != 1 {
		t.Fatalf("DeleteByUser removed %d, want 1", n)
	}
	n, _ = ss.DeleteByUser(ctx, u.ID)
	if n != 0 {
		t.Fatal("second DeleteByUser removed something")
	}
	must(t, ss.Delete(ctx, core.HashToken("c")))
	_, err = ss.Get(ctx, core.HashToken("c"))
	wantErr(t, err, core.ErrNotFound)
}

func TestAccounts(t *testing.T) {
	s := open(t)
	as := s.Accounts()
	a := &core.ACMEAccount{ID: "acc1", Thumbprint: "tp1", JWK: []byte(`{"kty":"EC"}`), Status: core.AccountValid,
		Contact: []string{"mailto:a@example.com"}, CreatedAt: t0}
	must(t, as.Create(ctx, a))
	got, err := as.Get(ctx, "acc1")
	must(t, err)
	if !reflect.DeepEqual(got, a) {
		t.Fatalf("Get %+v, want %+v", got, a)
	}
	got, err = as.GetByThumbprint(ctx, "tp1")
	must(t, err)
	if got.ID != "acc1" {
		t.Fatal("GetByThumbprint")
	}

	wantErr(t, as.Create(ctx, &core.ACMEAccount{ID: "acc1", Thumbprint: "tp9", JWK: []byte("{}"), Status: core.AccountValid}), core.ErrConflict)
	wantErr(t, as.Create(ctx, &core.ACMEAccount{ID: "acc2", Thumbprint: "tp1", JWK: []byte("{}"), Status: core.AccountValid}), core.ErrConflict)
	must(t, as.Create(ctx, &core.ACMEAccount{ID: "acc2", Thumbprint: "tp2", JWK: []byte("{}"), Status: core.AccountValid}))
	b, _ := as.Get(ctx, "acc2")
	if b.Contact != nil {
		t.Fatalf("nil contact round-trips to %#v", b.Contact)
	}

	a.Contact, a.Status = nil, core.AccountDeactivated
	a.Thumbprint = "ignored"
	must(t, as.Update(ctx, a))
	got, _ = as.Get(ctx, "acc1")
	if got.Status != core.AccountDeactivated || got.Contact != nil || got.Thumbprint != "tp1" {
		t.Fatalf("after Update %+v", got)
	}
	wantErr(t, as.Update(ctx, &core.ACMEAccount{ID: "nope"}), core.ErrNotFound)

	must(t, as.UpdateKey(ctx, "acc1", []byte(`{"kty":"RSA"}`), "tp3"))
	got, _ = as.GetByThumbprint(ctx, "tp3")
	if got == nil || got.ID != "acc1" || string(got.JWK) != `{"kty":"RSA"}` {
		t.Fatalf("after UpdateKey %+v", got)
	}
	_, err = as.GetByThumbprint(ctx, "tp1")
	wantErr(t, err, core.ErrNotFound)
	wantErr(t, as.UpdateKey(ctx, "acc1", []byte("{}"), "tp2"), core.ErrConflict)
	wantErr(t, as.UpdateKey(ctx, "nope", []byte("{}"), "tp7"), core.ErrNotFound)
	_, err = as.Get(ctx, "nope")
	wantErr(t, err, core.ErrNotFound)
}
