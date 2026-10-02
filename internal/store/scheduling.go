package store

import (
	"context"
	"database/sql"
	"fmt"
	"net/netip"
	"time"

	"tls-broker/internal/core"
)

var (
	_ core.DirectStore        = (*directStore)(nil)
	_ core.ProviderStateStore = (*providerStateStore)(nil)
	_ core.BudgetStore        = (*budgetStore)(nil)
)

// ---------------------------------------------------------------------------
// Direct cache metadata
// ---------------------------------------------------------------------------

type directStore struct{ s *Store }

const directCols = `identifier, generation, certificate_id, provider, not_before, not_after, renew_at,
	next_ari_check_at, last_fetch_at, last_fetch_ip, last_attempt_at, last_error, failures, created_at, updated_at`

func scanDirect(r scanner) (*core.DirectEntry, error) {
	var e core.DirectEntry
	var ip string
	var nb, na, renew, ari, fetch, attempt, created, updated int64
	if err := r.Scan(&e.Identifier, &e.Generation, &e.CertificateID, &e.Provider, &nb, &na, &renew,
		&ari, &fetch, &ip, &attempt, &e.LastError, &e.Failures, &created, &updated); err != nil {
		return nil, err
	}
	a, err := parseAddr(ip)
	if err != nil {
		return nil, fmt.Errorf("stored fetch address %q: %w", ip, err)
	}
	e.LastFetchIP = a
	e.NotBefore, e.NotAfter, e.RenewAt, e.NextARICheckAt = tm(nb), tm(na), tm(renew), tm(ari)
	e.LastFetchAt, e.LastAttemptAt, e.CreatedAt, e.UpdatedAt = tm(fetch), tm(attempt), tm(created), tm(updated)
	return &e, nil
}

func (st *directStore) Get(ctx context.Context, identifier string) (*core.DirectEntry, error) {
	e, err := queryOne(ctx, st.s.r, scanDirect, "direct entry", identifier,
		`SELECT `+directCols+` FROM direct_entries WHERE identifier = ?`, identifier)
	return e, wrap(err)
}

func (st *directStore) Put(ctx context.Context, e *core.DirectEntry) error {
	if e.Identifier == "" {
		return fmt.Errorf("store: direct entry without identifier")
	}
	return st.s.write(ctx, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, `INSERT INTO direct_entries (`+directCols+`)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
			ON CONFLICT (identifier) DO UPDATE SET
				generation = excluded.generation, certificate_id = excluded.certificate_id,
				provider = excluded.provider, not_before = excluded.not_before, not_after = excluded.not_after,
				renew_at = excluded.renew_at, next_ari_check_at = excluded.next_ari_check_at,
				last_attempt_at = excluded.last_attempt_at, last_error = excluded.last_error,
				failures = excluded.failures, updated_at = excluded.updated_at`,
			e.Identifier, e.Generation, e.CertificateID, e.Provider, ts(e.NotBefore), ts(e.NotAfter), ts(e.RenewAt),
			ts(e.NextARICheckAt), ts(e.LastFetchAt), addrText(e.LastFetchIP), ts(e.LastAttemptAt), e.LastError,
			e.Failures, ts(e.CreatedAt), ts(e.UpdatedAt))
		return err
	})
}

func (st *directStore) TouchFetch(ctx context.Context, identifier string, at time.Time, src netip.Addr) error {
	return st.s.write(ctx, func(tx *sql.Tx) error {
		res, err := tx.ExecContext(ctx, `UPDATE direct_entries SET last_fetch_at = ?, last_fetch_ip = ?
			WHERE identifier = ?`, ts(at), addrText(src), identifier)
		if err != nil {
			return err
		}
		return mustAffect(res, "direct entry", identifier)
	})
}

func (st *directStore) List(ctx context.Context) ([]core.DirectEntry, error) {
	list, err := queryAll(ctx, st.s.r, scanDirect, `SELECT `+directCols+` FROM direct_entries ORDER BY identifier`)
	return deref(list), wrap(err)
}

func (st *directStore) Delete(ctx context.Context, identifier string) error {
	_, err := execCount(ctx, st.s, `DELETE FROM direct_entries WHERE identifier = ?`, identifier)
	return err
}

// ---------------------------------------------------------------------------
// Provider circuit state
// ---------------------------------------------------------------------------

type providerStateStore struct{ s *Store }

const providerCols = `name, health, retry_after, last_error, failures, updated_at`

func scanProviderState(r scanner) (*core.ProviderState, error) {
	var p core.ProviderState
	var health string
	var retry, updated int64
	if err := r.Scan(&p.Name, &health, &retry, &p.LastError, &p.Failures, &updated); err != nil {
		return nil, err
	}
	p.Health, p.RetryAfter, p.UpdatedAt = core.ProviderHealth(health), tm(retry), tm(updated)
	return &p, nil
}

func (st *providerStateStore) Get(ctx context.Context, name string) (*core.ProviderState, error) {
	p, err := queryOne(ctx, st.s.r, scanProviderState, "provider state", name,
		`SELECT `+providerCols+` FROM provider_states WHERE name = ?`, name)
	return p, wrap(err)
}

func (st *providerStateStore) Put(ctx context.Context, p *core.ProviderState) error {
	if p.Name == "" {
		return fmt.Errorf("store: provider state without name")
	}
	return st.s.write(ctx, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, `INSERT INTO provider_states (`+providerCols+`) VALUES (?, ?, ?, ?, ?, ?)
			ON CONFLICT (name) DO UPDATE SET health = excluded.health, retry_after = excluded.retry_after,
			last_error = excluded.last_error, failures = excluded.failures, updated_at = excluded.updated_at`,
			p.Name, string(p.Health), ts(p.RetryAfter), p.LastError, p.Failures, ts(p.UpdatedAt))
		return err
	})
}

func (st *providerStateStore) List(ctx context.Context) ([]core.ProviderState, error) {
	list, err := queryAll(ctx, st.s.r, scanProviderState, `SELECT `+providerCols+` FROM provider_states ORDER BY name`)
	return deref(list), wrap(err)
}

// ---------------------------------------------------------------------------
// Budget events
// ---------------------------------------------------------------------------

type budgetStore struct{ s *Store }

const budgetCols = `id, ref, provider, kind, key, at, state, renewal`

func scanBudget(r scanner) (*core.BudgetEvent, error) {
	var e core.BudgetEvent
	var kind, state string
	var at int64
	if err := r.Scan(&e.ID, &e.Ref, &e.Provider, &kind, &e.Key, &at, &state, &e.Renewal); err != nil {
		return nil, err
	}
	e.Kind, e.State, e.At = core.BudgetKind(kind), core.BudgetState(state), tm(at)
	return &e, nil
}

func (st *budgetStore) Reserve(ctx context.Context, events []core.BudgetEvent) error {
	if len(events) == 0 {
		return nil
	}
	ref := events[0].Ref
	for _, e := range events {
		if e.Ref == "" || e.Ref != ref {
			return fmt.Errorf("store: budget events of one Reserve must share one non-empty ref")
		}
	}
	ids := make([]int64, len(events))
	err := st.s.write(ctx, func(tx *sql.Tx) error {
		for i, e := range events {
			res, err := tx.ExecContext(ctx, `INSERT INTO budget_events (ref, provider, kind, key, at, state, renewal)
				VALUES (?, ?, ?, ?, ?, 'reserved', ?)`, e.Ref, e.Provider, string(e.Kind), e.Key, ts(e.At), b2i(e.Renewal))
			if err != nil {
				return err
			}
			if ids[i], err = res.LastInsertId(); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		return err
	}
	for i := range events {
		events[i].ID = ids[i]
		events[i].State = core.BudgetReserved
	}
	return nil
}

// kindFilter returns " AND kind IN (...)" and its arguments; empty for no
// kinds (every kind).
func kindFilter(kinds []core.BudgetKind) (string, []any) {
	if len(kinds) == 0 {
		return "", nil
	}
	args := make([]any, len(kinds))
	for i, k := range kinds {
		args[i] = string(k)
	}
	return ` AND kind IN (` + inList(len(kinds)) + `)`, args
}

func (st *budgetStore) Commit(ctx context.Context, ref string, kinds ...core.BudgetKind) error {
	f, args := kindFilter(kinds)
	_, err := execCount(ctx, st.s, `UPDATE budget_events SET state = 'committed'
		WHERE ref = ? AND state = 'reserved'`+f, append([]any{ref}, args...)...)
	return err
}

func (st *budgetStore) Release(ctx context.Context, ref string, kinds ...core.BudgetKind) error {
	f, args := kindFilter(kinds)
	_, err := execCount(ctx, st.s, `DELETE FROM budget_events WHERE ref = ? AND state = 'reserved'`+f,
		append([]any{ref}, args...)...)
	return err
}

func (st *budgetStore) list(ctx context.Context, tail string, args ...any) ([]core.BudgetEvent, error) {
	list, err := queryAll(ctx, st.s.r, scanBudget, `SELECT `+budgetCols+` FROM budget_events `+tail, args...)
	return deref(list), wrap(err)
}

func (st *budgetStore) ListByRef(ctx context.Context, ref string) ([]core.BudgetEvent, error) {
	return st.list(ctx, `WHERE ref = ? ORDER BY id`, ref)
}

func (st *budgetStore) ListSince(ctx context.Context, since time.Time) ([]core.BudgetEvent, error) {
	return st.list(ctx, `WHERE at >= ? ORDER BY at, id`, ts(since))
}

func (st *budgetStore) ListReserved(ctx context.Context) ([]core.BudgetEvent, error) {
	return st.list(ctx, `WHERE state = 'reserved' ORDER BY id`)
}

func (st *budgetStore) Prune(ctx context.Context, before time.Time) (int, error) {
	return execCount(ctx, st.s, `DELETE FROM budget_events WHERE state = 'committed' AND at < ?`, ts(before))
}
