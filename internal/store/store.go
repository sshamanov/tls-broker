// Package store implements every store interface of package core on one
// SQLite database (modernc.org/sqlite, no cgo). See docs/data-model.md for
// the schema and the state machines it enforces.
//
// Concurrency: the database runs in WAL mode. All writes go through a pool of
// exactly one connection and every write transaction starts with BEGIN
// IMMEDIATE, so writers are serialized in-process and never deadlock or hit
// SQLITE_BUSY_SNAPSHOT; a read-then-write method therefore sees no change
// between its read and its write. Pure reads use a separate read-only pool
// and never wait for writers.
package store

import (
	"context"
	"database/sql"
	"embed"
	"errors"
	"fmt"
	"io/fs"
	"math"
	"net/netip"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"modernc.org/sqlite"
	sqlite3 "modernc.org/sqlite/lib"

	"tls-broker/internal/core"
	"tls-broker/internal/names"
)

//go:embed migrations/*.sql
var migrationFS embed.FS

// busyTimeout bounds how long a connection waits for a lock held by another
// process (a backup tool, the sqlite3 shell). In-process writers never wait
// on each other at the SQLite level.
const busyTimeout = 10 * time.Second

// maxReaders is the size of the read-only connection pool.
const maxReaders = 8

// Store is the SQLite database. It is safe for concurrent use. Obtain the
// individual core stores with the accessor methods.
type Store struct {
	path string
	w    *sql.DB // single writer connection
	r    *sql.DB // read-only pool

	users      *userStore
	grants     *grantStore
	sessions   *sessionStore
	accounts   *accountStore
	orders     *orderStore
	certs      *certificateStore
	lineages   *lineageStore
	challenges *challengeStore
	direct     *directStore
	providers  *providerStateStore
	budgets    *budgetStore
}

// Open opens (creating if needed) the database at path and applies every
// pending migration. It refuses a database written by a newer schema.
func Open(path string) (*Store, error) {
	if path == "" || strings.ContainsAny(path, "?#") {
		return nil, fmt.Errorf("store: invalid database path %q", path)
	}
	bt := strconv.FormatInt(busyTimeout.Milliseconds(), 10)
	wdsn := path + "?_txlock=immediate" +
		"&_pragma=busy_timeout(" + bt + ")" +
		"&_pragma=journal_mode(WAL)" +
		"&_pragma=synchronous(FULL)" +
		"&_pragma=foreign_keys(1)"
	w, err := sql.Open("sqlite", wdsn)
	if err != nil {
		return nil, fmt.Errorf("store: open %s: %w", path, err)
	}
	w.SetMaxOpenConns(1)
	w.SetMaxIdleConns(1)
	w.SetConnMaxLifetime(0)
	w.SetConnMaxIdleTime(0)
	if err := migrate(context.Background(), w); err != nil {
		w.Close()
		return nil, fmt.Errorf("store: %s: %w", path, err)
	}
	rdsn := path + "?_pragma=busy_timeout(" + bt + ")" +
		"&_pragma=query_only(1)" +
		"&_pragma=foreign_keys(1)"
	r, err := sql.Open("sqlite", rdsn)
	if err != nil {
		w.Close()
		return nil, fmt.Errorf("store: open %s: %w", path, err)
	}
	r.SetMaxOpenConns(maxReaders)
	r.SetMaxIdleConns(maxReaders)
	if err := r.Ping(); err != nil {
		w.Close()
		r.Close()
		return nil, fmt.Errorf("store: open %s: %w", path, err)
	}
	s := &Store{path: path, w: w, r: r}
	s.users = &userStore{s}
	s.grants = &grantStore{s}
	s.sessions = &sessionStore{s}
	s.accounts = &accountStore{s}
	s.orders = &orderStore{s}
	s.certs = &certificateStore{s}
	s.lineages = &lineageStore{s}
	s.challenges = &challengeStore{s}
	s.direct = &directStore{s}
	s.providers = &providerStateStore{s}
	s.budgets = &budgetStore{s}
	return s, nil
}

// Close closes the database. The WAL is checkpointed by SQLite when the last
// connection closes.
func (s *Store) Close() error {
	rerr := s.r.Close()
	werr := s.w.Close()
	return errors.Join(rerr, werr)
}

// Users returns the user store.
func (s *Store) Users() core.UserStore { return s.users }

// Grants returns the IP grant store.
func (s *Store) Grants() core.GrantStore { return s.grants }

// Sessions returns the UI session store.
func (s *Store) Sessions() core.SessionStore { return s.sessions }

// Accounts returns the downstream ACME account store.
func (s *Store) Accounts() core.AccountStore { return s.accounts }

// Orders returns the order store.
func (s *Store) Orders() core.OrderStore { return s.orders }

// Certificates returns the certificate store.
func (s *Store) Certificates() core.CertificateStore { return s.certs }

// Lineages returns the lineage store.
func (s *Store) Lineages() core.LineageStore { return s.lineages }

// Challenges returns the DNS-01 challenge store.
func (s *Store) Challenges() core.ChallengeStore { return s.challenges }

// Direct returns the direct-cache metadata store.
func (s *Store) Direct() core.DirectStore { return s.direct }

// ProviderStates returns the provider circuit state store.
func (s *Store) ProviderStates() core.ProviderStateStore { return s.providers }

// Budgets returns the scheduler budget event store.
func (s *Store) Budgets() core.BudgetStore { return s.budgets }

// Backup writes a consistent snapshot of the live database to dest with
// VACUUM INTO (architecture §23). dest must not exist; the snapshot is a
// complete, compacted, self-contained database file (no WAL) that Open
// accepts as it is. Writers are not blocked while it runs.
func (s *Store) Backup(ctx context.Context, dest string) error {
	if dest == "" {
		return errors.New("store: backup: empty destination")
	}
	if _, err := os.Stat(dest); err == nil {
		return fmt.Errorf("store: backup: %s already exists", dest)
	} else if !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("store: backup: %w", err)
	}
	// A dedicated connection: the read pool is query_only and the writer must
	// stay free for writes. VACUUM INTO reads the source in one read
	// transaction, so the snapshot is consistent.
	b, err := sql.Open("sqlite", s.path+"?_pragma=busy_timeout("+strconv.FormatInt(busyTimeout.Milliseconds(), 10)+")")
	if err != nil {
		return fmt.Errorf("store: backup: %w", err)
	}
	defer b.Close()
	if _, err := b.ExecContext(ctx, "VACUUM INTO ?", dest); err != nil {
		os.Remove(dest)
		return fmt.Errorf("store: backup to %s: %w", dest, err)
	}
	return nil
}

// SchemaVersion returns the schema version of the open database.
func (s *Store) SchemaVersion(ctx context.Context) (int, error) {
	var v int
	if err := s.r.QueryRowContext(ctx, "PRAGMA user_version").Scan(&v); err != nil {
		return 0, fmt.Errorf("store: %w", err)
	}
	return v, nil
}

// ---------------------------------------------------------------------------
// Migrations
// ---------------------------------------------------------------------------

type migration struct {
	version int
	name    string
	sql     string
}

// migrations returns the embedded migrations ordered by version. Files are
// named NNNN_description.sql with versions 1, 2, 3, ... without gaps.
func migrations() ([]migration, error) {
	entries, err := fs.ReadDir(migrationFS, "migrations")
	if err != nil {
		return nil, err
	}
	var out []migration
	for _, e := range entries {
		n := e.Name()
		if !strings.HasSuffix(n, ".sql") {
			continue
		}
		num, _, ok := strings.Cut(n, "_")
		if !ok {
			return nil, fmt.Errorf("migration %s: name must be NNNN_description.sql", n)
		}
		v, err := strconv.Atoi(num)
		if err != nil || v <= 0 {
			return nil, fmt.Errorf("migration %s: bad version", n)
		}
		body, err := migrationFS.ReadFile("migrations/" + n)
		if err != nil {
			return nil, err
		}
		out = append(out, migration{version: v, name: n, sql: string(body)})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].version < out[j].version })
	for i, m := range out {
		if m.version != i+1 {
			return nil, fmt.Errorf("migration %s: expected version %d", m.name, i+1)
		}
	}
	return out, nil
}

// migrate applies pending migrations, each in its own transaction together
// with the PRAGMA user_version bump, so a crash leaves the database at a
// whole version. Migrations are forward-only.
func migrate(ctx context.Context, db *sql.DB) error {
	ms, err := migrations()
	if err != nil {
		return err
	}
	var cur int
	if err := db.QueryRowContext(ctx, "PRAGMA user_version").Scan(&cur); err != nil {
		return fmt.Errorf("read schema version: %w", err)
	}
	if cur > len(ms) {
		return fmt.Errorf("database schema version %d is newer than this binary supports (%d)", cur, len(ms))
	}
	for _, m := range ms[cur:] {
		tx, err := db.BeginTx(ctx, nil)
		if err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, m.sql); err != nil {
			tx.Rollback()
			return fmt.Errorf("migration %s: %w", m.name, err)
		}
		if _, err := tx.ExecContext(ctx, fmt.Sprintf("PRAGMA user_version = %d", m.version)); err != nil {
			tx.Rollback()
			return fmt.Errorf("migration %s: %w", m.name, err)
		}
		if err := tx.Commit(); err != nil {
			return fmt.Errorf("migration %s: %w", m.name, err)
		}
	}
	return nil
}

// ---------------------------------------------------------------------------
// Transactions and errors
// ---------------------------------------------------------------------------

// write runs fn in one IMMEDIATE transaction on the single writer connection
// and commits it when fn returns nil.
func (s *Store) write(ctx context.Context, fn func(tx *sql.Tx) error) error {
	tx, err := s.w.BeginTx(ctx, nil)
	if err != nil {
		return wrap(err)
	}
	if err := fn(tx); err != nil {
		tx.Rollback()
		return wrap(err)
	}
	if err := tx.Commit(); err != nil {
		return wrap(err)
	}
	return nil
}

// wrap maps SQLite constraint violations to core.ErrConflict and prefixes
// errors with the package name once.
func wrap(err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, core.ErrNotFound) || errors.Is(err, core.ErrConflict) ||
		errors.Is(err, core.ErrExpired) || errors.Is(err, core.ErrCSRMismatch) {
		return err
	}
	var se *sqlite.Error
	if errors.As(err, &se) && se.Code()&0xff == sqlite3.SQLITE_CONSTRAINT {
		return fmt.Errorf("store: %s: %w", se.Error(), core.ErrConflict)
	}
	if strings.HasPrefix(err.Error(), "store: ") {
		return err
	}
	return fmt.Errorf("store: %w", err)
}

func isNotFound(err error) bool { return errors.Is(err, core.ErrNotFound) }

func notFound(what, id string) error {
	return fmt.Errorf("store: %s %q: %w", what, id, core.ErrNotFound)
}

func conflict(format string, args ...any) error {
	return fmt.Errorf("store: "+format+": %w", append(args, core.ErrConflict)...)
}

// mustAffect turns "no row changed" into ErrNotFound.
func mustAffect(res sql.Result, what, id string) error {
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return notFound(what, id)
	}
	return nil
}

// ---------------------------------------------------------------------------
// Value encoding
// ---------------------------------------------------------------------------

var (
	minTime = time.Unix(0, math.MinInt64+1).UTC()
	maxTime = time.Unix(0, math.MaxInt64).UTC()
)

// ts encodes a time as Unix nanoseconds, 0 for the zero time. Times outside
// the representable range (years 1678–2262) are clamped to it.
func ts(t time.Time) int64 {
	if t.IsZero() {
		return 0
	}
	if t.Before(minTime) {
		return minTime.UnixNano()
	}
	if t.After(maxTime) {
		return math.MaxInt64
	}
	return t.UnixNano()
}

// tm decodes ts.
func tm(n int64) time.Time {
	if n == 0 {
		return time.Time{}
	}
	return time.Unix(0, n).UTC()
}

func b2i(b bool) int {
	if b {
		return 1
	}
	return 0
}

func addrText(a netip.Addr) string {
	if !a.IsValid() {
		return ""
	}
	return a.String()
}

func parseAddr(s string) (netip.Addr, error) {
	if s == "" {
		return netip.Addr{}, nil
	}
	return netip.ParseAddr(s)
}

func parseSet(key string) (names.Set, error) {
	set, err := names.ParseKey(key)
	if err != nil {
		return names.Set{}, fmt.Errorf("stored identifier set %q: %w", key, err)
	}
	return set, nil
}

// scanner is *sql.Row or *sql.Rows.
type scanner interface{ Scan(dest ...any) error }

// queryRow runs a single-row query and maps sql.ErrNoRows to ErrNotFound.
func queryOne[T any](ctx context.Context, q interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
}, scan func(scanner) (T, error), what, id, query string, args ...any) (T, error) {
	v, err := scan(q.QueryRowContext(ctx, query, args...))
	if errors.Is(err, sql.ErrNoRows) {
		var zero T
		return zero, notFound(what, id)
	}
	return v, err
}

// queryAll runs a query and scans every row; an empty result is an empty,
// non-nil slice.
func queryAll[T any](ctx context.Context, q interface {
	QueryContext(context.Context, string, ...any) (*sql.Rows, error)
}, scan func(scanner) (T, error), query string, args ...any) ([]T, error) {
	rows, err := q.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []T{}
	for rows.Next() {
		v, err := scan(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, rows.Err()
}

// inList returns "?, ?, ..." for n parameters.
func inList(n int) string {
	return strings.TrimSuffix(strings.Repeat("?, ", n), ", ")
}
