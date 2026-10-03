package store

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"tls-broker/internal/core"
)

var (
	_ core.CertificateStore = (*certificateStore)(nil)
	_ core.LineageStore     = (*lineageStore)(nil)
)

// ---------------------------------------------------------------------------
// Certificates
// ---------------------------------------------------------------------------

type certificateStore struct{ s *Store }

const certMetaCols = `id, order_id, mode, set_key, provider, account_url, serial, ari_cert_id,
	not_before, not_after, issued_at, replaces_id, replaced_by_id, source_ip, grant_id`

const certCols = certMetaCols + `, chain_pem`

func scanCertMeta(r scanner, extra ...any) (*core.Certificate, error) {
	var c core.Certificate
	var mode, setKey, ip string
	var nb, na, issued int64
	dest := []any{&c.ID, &c.OrderID, &mode, &setKey, &c.Provider, &c.AccountURL, &c.Serial, &c.ARICertID,
		&nb, &na, &issued, &c.ReplacesID, &c.ReplacedByID, &ip, &c.GrantID}
	if err := r.Scan(append(dest, extra...)...); err != nil {
		return nil, err
	}
	set, err := parseSet(setKey)
	if err != nil {
		return nil, err
	}
	c.Names, c.Mode = set, core.Mode(mode)
	if c.SourceIP, err = parseAddr(ip); err != nil {
		return nil, err
	}
	c.NotBefore, c.NotAfter, c.IssuedAt = tm(nb), tm(na), tm(issued)
	return &c, nil
}

func scanCertificate(r scanner) (*core.Certificate, error) {
	var chain []byte
	c, err := scanCertMeta(r, &chain)
	if err != nil {
		return nil, err
	}
	if len(chain) > 0 {
		c.ChainPEM = chain
	}
	return c, nil
}

func scanCertificateMeta(r scanner) (*core.Certificate, error) { return scanCertMeta(r) }

// insertCertificate is used only by OrderStore.Complete. The chain is stored
// for ACME-mode certificates only; direct-mode material lives on disk.
func insertCertificate(ctx context.Context, tx *sql.Tx, c *core.Certificate, orderMode core.Mode) error {
	if c.Names.IsZero() {
		return fmt.Errorf("certificate %q: empty identifier set", c.ID)
	}
	var chain any
	if c.Mode != core.ModeDirect && orderMode != core.ModeDirect && len(c.ChainPEM) > 0 {
		chain = c.ChainPEM
	}
	_, err := tx.ExecContext(ctx, `INSERT INTO certificates (`+certCols+`)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		c.ID, c.OrderID, string(c.Mode), c.Names.Key(), c.Provider, c.AccountURL, c.Serial, c.ARICertID,
		ts(c.NotBefore), ts(c.NotAfter), ts(c.IssuedAt), c.ReplacesID, c.ReplacedByID,
		addrText(c.SourceIP), c.GrantID, chain)
	return err
}

func (st *certificateStore) Get(ctx context.Context, id string) (*core.Certificate, error) {
	c, err := queryOne(ctx, st.s.r, scanCertificate, "certificate", id,
		`SELECT `+certCols+` FROM certificates WHERE id = ?`, id)
	return c, wrap(err)
}

func (st *certificateStore) GetByARICertID(ctx context.Context, ariCertID string) (*core.Certificate, error) {
	if ariCertID == "" {
		return nil, notFound("certificate with ARI identifier", ariCertID)
	}
	c, err := queryOne(ctx, st.s.r, scanCertificate, "certificate with ARI identifier", ariCertID,
		`SELECT `+certCols+` FROM certificates WHERE ari_cert_id = ?`, ariCertID)
	return c, wrap(err)
}

func (st *certificateStore) Newest(ctx context.Context, setKey, provider string) (*core.Certificate, error) {
	c, err := queryOne(ctx, st.s.r, scanCertificate, "certificate for", setKey,
		`SELECT `+certCols+` FROM certificates WHERE set_key = ? AND (? = '' OR provider = ?)
		ORDER BY not_before DESC, issued_at DESC, rowid DESC LIMIT 1`, setKey, provider, provider)
	return c, wrap(err)
}

func (st *certificateStore) NewestUnreplaced(ctx context.Context, setKey, provider string, now time.Time) (*core.Certificate, error) {
	if provider == "" {
		return nil, fmt.Errorf("store: NewestUnreplaced needs a provider")
	}
	c, err := queryOne(ctx, st.s.r, scanCertificate, "unreplaced certificate for", setKey,
		`SELECT `+certCols+` FROM certificates
		WHERE set_key = ? AND provider = ? AND replaced_by_id = '' AND not_after > ?
		ORDER BY not_before DESC, issued_at DESC, rowid DESC LIMIT 1`, setKey, provider, ts(now))
	return c, wrap(err)
}

func (st *certificateStore) MarkReplaced(ctx context.Context, id, byID string) error {
	if byID == "" {
		return fmt.Errorf("store: certificate %q: empty replacement ID", id)
	}
	return st.s.write(ctx, func(tx *sql.Tx) error {
		var cur string
		if err := tx.QueryRowContext(ctx, `SELECT replaced_by_id FROM certificates WHERE id = ?`, id).Scan(&cur); err == sql.ErrNoRows {
			return notFound("certificate", id)
		} else if err != nil {
			return err
		}
		if cur != "" {
			return nil
		}
		_, err := tx.ExecContext(ctx, `UPDATE certificates SET replaced_by_id = ? WHERE id = ?`, byID, id)
		return err
	})
}

func (st *certificateStore) List(ctx context.Context, f core.CertificateFilter) ([]core.Certificate, error) {
	q := `SELECT ` + certMetaCols + ` FROM certificates WHERE 1 = 1`
	var args []any
	if f.Mode != "" {
		q += ` AND mode = ?`
		args = append(args, string(f.Mode))
	}
	if f.Provider != "" {
		q += ` AND provider = ?`
		args = append(args, f.Provider)
	}
	if f.NameContains != "" {
		q += ` AND instr(set_key, ?) > 0`
		args = append(args, f.NameContains)
	}
	if !f.ValidAt.IsZero() {
		q += ` AND not_after > ?`
		args = append(args, ts(f.ValidAt))
	}
	q += ` ORDER BY not_before DESC, issued_at DESC, rowid DESC LIMIT ? OFFSET ?`
	args = append(args, limit(f.Limit), max(f.Offset, 0))
	list, err := queryAll(ctx, st.s.r, scanCertificateMeta, q, args...)
	return deref(list), wrap(err)
}

func (st *certificateStore) DropChains(ctx context.Context, before time.Time) (int, error) {
	return execCount(ctx, st.s, `UPDATE certificates SET chain_pem = NULL
		WHERE chain_pem IS NOT NULL AND not_after < ?`, ts(before))
}

// ---------------------------------------------------------------------------
// Lineages
// ---------------------------------------------------------------------------

type lineageStore struct{ s *Store }

func scanLineage(r scanner) (*core.Lineage, error) {
	var l core.Lineage
	var last, interval int64
	if err := r.Scan(&l.Key, &last, &interval, &l.Samples); err != nil {
		return nil, err
	}
	l.LastRequestAt, l.ObservedInterval = tm(last), time.Duration(interval)
	return &l, nil
}

const lineageSelect = `SELECT key, last_request_at, observed_interval, samples FROM lineages WHERE key = ?`

func (st *lineageStore) Get(ctx context.Context, key string) (*core.Lineage, error) {
	l, err := queryOne(ctx, st.s.r, scanLineage, "lineage", key, lineageSelect, key)
	return l, wrap(err)
}

func (st *lineageStore) Observe(ctx context.Context, key string, at time.Time) (core.Lineage, error) {
	var out core.Lineage
	err := st.s.write(ctx, func(tx *sql.Tx) error {
		cur := core.Lineage{Key: key}
		l, err := queryOne(ctx, tx, scanLineage, "lineage", key, lineageSelect, key)
		switch {
		case err == nil:
			cur = *l
		case !isNotFound(err):
			return err
		}
		out = cur.Observe(at)
		// Round-trip the stored representation so the caller sees what a
		// later Get returns.
		out.LastRequestAt = tm(ts(out.LastRequestAt))
		_, err = tx.ExecContext(ctx, `INSERT INTO lineages (key, last_request_at, observed_interval, samples)
			VALUES (?, ?, ?, ?) ON CONFLICT (key) DO UPDATE SET
			last_request_at = excluded.last_request_at, observed_interval = excluded.observed_interval,
			samples = excluded.samples`,
			key, ts(out.LastRequestAt), int64(out.ObservedInterval), out.Samples)
		return err
	})
	if err != nil {
		return core.Lineage{}, err
	}
	return out, nil
}
