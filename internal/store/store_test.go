package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/netip"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"tls-broker/internal/core"
	"tls-broker/internal/names"
)

var (
	ctx = context.Background()
	t0  = time.Date(2026, 10, 1, 12, 0, 0, 123456789, time.UTC)
)

func dbPath(t *testing.T) string { return filepath.Join(t.TempDir(), "state.db") }

func openAt(t *testing.T, path string) *Store {
	t.Helper()
	s, err := Open(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func open(t *testing.T) *Store { return openAt(t, dbPath(t)) }

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

func wantErr(t *testing.T, err, target error) {
	t.Helper()
	if !errors.Is(err, target) {
		t.Fatalf("got error %v, want %v", err, target)
	}
}

func TestOpenMigratesEmptyDatabase(t *testing.T) {
	s := open(t)
	v, err := s.SchemaVersion(ctx)
	must(t, err)
	ms, err := migrations()
	must(t, err)
	if v != len(ms) || v < 1 {
		t.Fatalf("schema version %d, want %d", v, len(ms))
	}
	var mode string
	must(t, s.w.QueryRow("PRAGMA journal_mode").Scan(&mode))
	if mode != "wal" {
		t.Fatalf("journal_mode %q, want wal", mode)
	}
	var fk int
	must(t, s.w.QueryRow("PRAGMA foreign_keys").Scan(&fk))
	if fk != 1 {
		t.Fatal("foreign keys are off")
	}
	for _, table := range []string{"users", "grants", "sessions", "acme_accounts", "orders", "certificates",
		"lineages", "challenges", "direct_entries", "provider_states", "budget_events"} {
		var n int
		must(t, s.r.QueryRow(`SELECT count(*) FROM sqlite_master WHERE type = 'table' AND name = ?`, table).Scan(&n))
		if n != 1 {
			t.Errorf("table %s missing", table)
		}
	}
}

func TestReadPoolIsReadOnly(t *testing.T) {
	s := open(t)
	if _, err := s.r.Exec(`INSERT INTO lineages (key) VALUES ('x')`); err == nil {
		t.Fatal("write through the read pool succeeded")
	}
}

func TestReopenPersistsAndIsIdempotent(t *testing.T) {
	path := dbPath(t)
	s, err := Open(path)
	must(t, err)
	u, _, err := s.Users().Ensure(ctx, "alice", false, t0)
	must(t, err)
	must(t, s.Close())

	s2 := openAt(t, path)
	got, err := s2.Users().Get(ctx, u.ID)
	must(t, err)
	if got.Username != "alice" || !got.CreatedAt.Equal(t0) {
		t.Fatalf("after reopen: %+v", got)
	}
	v, err := s2.SchemaVersion(ctx)
	must(t, err)
	ms, _ := migrations()
	if v != len(ms) {
		t.Fatalf("version %d after reopen", v)
	}
}

func TestOpenRefusesNewerSchema(t *testing.T) {
	path := dbPath(t)
	s, err := Open(path)
	must(t, err)
	_, err = s.w.Exec("PRAGMA user_version = 999")
	must(t, err)
	must(t, s.Close())
	if s, err := Open(path); err == nil {
		s.Close()
		t.Fatal("opened a database with a newer schema")
	} else if !strings.Contains(err.Error(), "newer") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestOpenRejectsBadPath(t *testing.T) {
	for _, p := range []string{"", "a?b.db", "a#b.db"} {
		if s, err := Open(p); err == nil {
			s.Close()
			t.Errorf("Open(%q) succeeded", p)
		}
	}
}

func TestMigrationsAreSequential(t *testing.T) {
	ms, err := migrations()
	must(t, err)
	for i, m := range ms {
		if m.version != i+1 || strings.TrimSpace(m.sql) == "" {
			t.Fatalf("migration %d: %+v", i, m.name)
		}
	}
}

func TestBackupIsConsistentSnapshot(t *testing.T) {
	s := open(t)
	_, _, err := s.Users().Ensure(ctx, "alice", false, t0)
	must(t, err)
	dir := t.TempDir()
	dest := filepath.Join(dir, "backup.db")

	// Writers keep going while the backup runs.
	var wg sync.WaitGroup
	stop := make(chan struct{})
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; ; i++ {
			select {
			case <-stop:
				return
			default:
			}
			if _, _, err := s.Users().Ensure(ctx, fmt.Sprintf("u%04d", i), false, t0); err != nil {
				t.Error(err)
				return
			}
		}
	}()
	must(t, s.Backup(ctx, dest))
	close(stop)
	wg.Wait()

	b := openAt(t, dest)
	if _, err := b.Users().GetByUsername(ctx, "alice", false); err != nil {
		t.Fatalf("backup lacks data: %v", err)
	}
	var ok string
	must(t, b.r.QueryRow("PRAGMA integrity_check").Scan(&ok))
	if ok != "ok" {
		t.Fatalf("integrity_check: %s", ok)
	}

	if err := s.Backup(ctx, dest); err == nil {
		t.Fatal("backup over an existing file succeeded")
	}
	if err := s.Backup(ctx, ""); err == nil {
		t.Fatal("backup to empty path succeeded")
	}
}

func TestConcurrentWritersAndReaders(t *testing.T) {
	s := open(t)
	const n = 40
	var wg sync.WaitGroup
	errs := make(chan error, 2*n)
	for i := 0; i < n; i++ {
		wg.Add(2)
		go func(i int) {
			defer wg.Done()
			u, _, err := s.Users().Ensure(ctx, fmt.Sprintf("user%02d", i), false, t0)
			if err != nil {
				errs <- err
				return
			}
			if err := s.Users().SetRole(ctx, u.ID, core.RoleAdmin); err != nil {
				errs <- err
			}
		}(i)
		go func() {
			defer wg.Done()
			if _, err := s.Users().List(ctx); err != nil {
				errs <- err
			}
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatal(err)
	}
	us, err := s.Users().List(ctx)
	must(t, err)
	if len(us) != n {
		t.Fatalf("%d users, want %d", len(us), n)
	}
}

func TestCanceledContext(t *testing.T) {
	s := open(t)
	c, cancel := context.WithCancel(ctx)
	cancel()
	if _, _, err := s.Users().Ensure(c, "x", false, t0); !errors.Is(err, context.Canceled) {
		t.Fatalf("write with canceled context: %v", err)
	}
	if _, err := s.Users().List(c); !errors.Is(err, context.Canceled) {
		t.Fatalf("read with canceled context: %v", err)
	}
}

func TestTimeEncoding(t *testing.T) {
	for _, tc := range []time.Time{
		{},
		t0,
		t0.In(time.FixedZone("x", 3600)),
		time.Date(1600, 1, 1, 0, 0, 0, 0, time.UTC),
		time.Date(3000, 1, 1, 0, 0, 0, 0, time.UTC),
	} {
		got := tm(ts(tc))
		switch {
		case tc.IsZero():
			if !got.IsZero() {
				t.Errorf("zero time round-trips to %v", got)
			}
		case tc.Year() < 1678 || tc.Year() > 2261:
			if got.IsZero() || got.Location() != time.UTC {
				t.Errorf("%v clamped to %v", tc, got)
			}
		default:
			if !got.Equal(tc) || got.Location() != time.UTC {
				t.Errorf("%v round-trips to %v", tc, got)
			}
		}
	}
}

// TestNoPrivateKeysStored runs a direct-mode issuance whose certificate
// struct carries a chain and checks that no PEM private key, and no chain of
// a direct certificate, ends up anywhere in the database.
func TestNoPrivateKeysStored(t *testing.T) {
	s := open(t)
	o := newOrder("d1", "dev.example.com")
	o.Mode, o.AccountID = core.ModeDirect, ""
	must(t, s.Orders().Create(ctx, o))
	_, _, err := s.Orders().BeginFinalize(ctx, "d1", "h", []byte("csr"), t0)
	must(t, err)
	c := newCert("c1", "d1", o.Names, t0)
	c.Mode = core.ModeDirect
	c.ChainPEM = []byte("-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n" +
		"-----BEGIN RSA PRIVATE KEY-----\nBBBB\n-----END RSA PRIVATE KEY-----\n")
	must(t, s.Orders().Complete(ctx, "d1", c, t0))
	must(t, s.Direct().Put(ctx, &core.DirectEntry{Identifier: "dev.example.com", Generation: 1, CertificateID: "c1",
		CreatedAt: t0, UpdatedAt: t0}))

	got, err := s.Certificates().Get(ctx, "c1")
	must(t, err)
	if got.ChainPEM != nil {
		t.Fatal("direct-mode chain was stored")
	}
	assertNoText(t, s, "PRIVATE KEY")
	assertNoText(t, s, "BEGIN CERTIFICATE")
}

// assertNoText scans every column of every table for a substring.
func assertNoText(t *testing.T, s *Store, needle string) {
	t.Helper()
	tables, err := queryAll(ctx, s.r, func(r scanner) (string, error) {
		var n string
		return n, r.Scan(&n)
	}, `SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%'`)
	must(t, err)
	for _, table := range tables {
		rows, err := s.r.Query(`SELECT * FROM ` + table)
		must(t, err)
		cols, _ := rows.Columns()
		for rows.Next() {
			vals := make([]any, len(cols))
			ptrs := make([]any, len(cols))
			for i := range vals {
				ptrs[i] = &vals[i]
			}
			must(t, rows.Scan(ptrs...))
			for i, v := range vals {
				var str string
				switch v := v.(type) {
				case string:
					str = v
				case []byte:
					str = string(v)
				}
				if strings.Contains(str, needle) {
					t.Errorf("%s.%s contains %q", table, cols[i], needle)
				}
			}
		}
		must(t, rows.Err())
		rows.Close()
	}
}

// ---------------------------------------------------------------------------
// Fixtures shared by the order and certificate tests
// ---------------------------------------------------------------------------

func newOrder(id string, ns ...string) *core.Order {
	return &core.Order{
		ID:        id,
		Mode:      core.ModeACME,
		AccountID: "acct1",
		Names:     names.MustSet(ns...),
		SourceIP:  netip.MustParseAddr("10.0.0.5"),
		GrantID:   7,
		Status:    core.OrderReady,
		Prep:      core.PrepIntent,
		Class:     core.ClassACMEOrdinary,
		Provider:  "le",
		CreatedAt: t0,
		ExpiresAt: t0.Add(15 * time.Minute),
	}
}

func newCert(id, orderID string, set names.Set, notBefore time.Time) *core.Certificate {
	return &core.Certificate{
		ID:         id,
		OrderID:    orderID,
		Mode:       core.ModeACME,
		Names:      set,
		Provider:   "le",
		AccountURL: "https://ca.example/acct/1",
		Serial:     "0a" + id,
		ARICertID:  "aki." + id,
		NotBefore:  notBefore,
		NotAfter:   notBefore.Add(90 * 24 * time.Hour),
		IssuedAt:   notBefore.Add(time.Minute),
		ChainPEM:   []byte("chain of " + id),
	}
}

// rawExec runs SQL on the writer, for tests that need to set up states.
func rawExec(t *testing.T, s *Store, q string, args ...any) sql.Result {
	t.Helper()
	res, err := s.w.Exec(q, args...)
	must(t, err)
	return res
}
