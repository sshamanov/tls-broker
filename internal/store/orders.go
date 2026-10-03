package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"tls-broker/internal/core"
)

var _ core.OrderStore = (*orderStore)(nil)

type orderStore struct{ s *Store }

const orderCols = `id, mode, account_id, set_key, replaces, source_ip, grant_id, status, prep, class,
	ari_qualified, provider, upstream_order_url, upstream_replaces, upstream_expires_at,
	adopted_by_order_id, csr_hash, csr_der, certificate_id, error, created_at, expires_at, updated_at`

// adoptableWhere is the condition of CreateAdopting, on table alias-free
// columns of orders.
const adoptableWhere = `status = 'invalid' AND csr_hash = '' AND prep = 'prepared'
	AND upstream_order_url <> '' AND adopted_by_order_id = ''`

func scanOrder(r scanner) (*core.Order, error) {
	var o core.Order
	var mode, setKey, ip, status, prep, problem string
	var class int
	var upExp, created, expires, updated int64
	var certID sql.NullString
	if err := r.Scan(&o.ID, &mode, &o.AccountID, &setKey, &o.Replaces, &ip, &o.GrantID, &status, &prep, &class,
		&o.ARIQualified, &o.Provider, &o.UpstreamOrderURL, &o.UpstreamReplaces, &upExp,
		&o.AdoptedByOrderID, &o.CSRHash, &o.CSRDER, &certID, &problem, &created, &expires, &updated); err != nil {
		return nil, err
	}
	var err error
	if o.Names, err = parseSet(setKey); err != nil {
		return nil, err
	}
	if o.SourceIP, err = parseAddr(ip); err != nil {
		return nil, fmt.Errorf("stored order address %q: %w", ip, err)
	}
	if problem != "" {
		o.Error = new(core.Problem)
		if err := json.Unmarshal([]byte(problem), o.Error); err != nil {
			return nil, fmt.Errorf("stored order problem: %w", err)
		}
	}
	if len(o.CSRDER) == 0 {
		o.CSRDER = nil
	}
	o.Mode, o.Status, o.Prep, o.Class = core.Mode(mode), core.OrderStatus(status), core.PrepState(prep), core.PriorityClass(class)
	o.CertificateID = certID.String
	o.UpstreamExpiresAt, o.CreatedAt, o.ExpiresAt, o.UpdatedAt = tm(upExp), tm(created), tm(expires), tm(updated)
	return &o, nil
}

func problemJSON(p *core.Problem) (string, error) {
	if p == nil {
		return "", nil
	}
	b, err := json.Marshal(p)
	return string(b), err
}

func nullString(s string) any {
	if s == "" {
		return nil
	}
	return s
}

func getOrderTx(ctx context.Context, tx *sql.Tx, id string) (*core.Order, error) {
	return queryOne(ctx, tx, scanOrder, "order", id, `SELECT `+orderCols+` FROM orders WHERE id = ?`, id)
}

func insertOrder(ctx context.Context, tx *sql.Tx, o *core.Order, updated time.Time) error {
	problem, err := problemJSON(o.Error)
	if err != nil {
		return err
	}
	var csr any
	if len(o.CSRDER) > 0 {
		csr = o.CSRDER
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO orders (`+orderCols+`)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		o.ID, string(o.Mode), o.AccountID, o.Names.Key(), o.Replaces, addrText(o.SourceIP), o.GrantID,
		string(o.Status), string(o.Prep), int(o.Class), b2i(o.ARIQualified), o.Provider,
		o.UpstreamOrderURL, o.UpstreamReplaces, ts(o.UpstreamExpiresAt), o.AdoptedByOrderID,
		o.CSRHash, csr, nullString(o.CertificateID), problem,
		ts(o.CreatedAt), ts(o.ExpiresAt), ts(updated))
	return err
}

// createUpdatedAt is the UpdatedAt of a newly created order: as given, or
// CreatedAt when unset (Create has no `now` argument).
func createUpdatedAt(o *core.Order) time.Time {
	if !o.UpdatedAt.IsZero() {
		return o.UpdatedAt
	}
	return o.CreatedAt
}

func validateNew(o *core.Order) error {
	if o.ID == "" {
		return fmt.Errorf("store: order without ID")
	}
	if o.Mode != core.ModeACME && o.Mode != core.ModeDirect {
		return fmt.Errorf("store: order %q: invalid mode %q", o.ID, o.Mode)
	}
	if o.Names.IsZero() {
		return fmt.Errorf("store: order %q: empty identifier set", o.ID)
	}
	if o.Provider == "" {
		return fmt.Errorf("store: order %q: no provider", o.ID)
	}
	if o.Status != core.OrderReady {
		return conflict("new order %q must have status ready, not %q", o.ID, o.Status)
	}
	if o.CSRHash != "" || len(o.CSRDER) > 0 || o.CertificateID != "" || o.AdoptedByOrderID != "" {
		return conflict("new order %q carries finalize, certificate or adoption state", o.ID)
	}
	return nil
}

func (st *orderStore) Create(ctx context.Context, o *core.Order) error {
	if err := validateNew(o); err != nil {
		return err
	}
	if o.Prep != core.PrepIntent {
		return conflict("new order %q must have prep intent, not %q", o.ID, o.Prep)
	}
	updated := createUpdatedAt(o)
	err := st.s.write(ctx, func(tx *sql.Tx) error { return insertOrder(ctx, tx, o, updated) })
	if err != nil {
		return err
	}
	o.UpdatedAt = updated
	return nil
}

func (st *orderStore) CreateAdopting(ctx context.Context, o *core.Order, donorID string) error {
	if err := validateNew(o); err != nil {
		return err
	}
	updated := createUpdatedAt(o)
	var donor *core.Order
	err := st.s.write(ctx, func(tx *sql.Tx) error {
		var err error
		donor, err = getOrderTx(ctx, tx, donorID)
		if err != nil {
			return err
		}
		switch {
		case donor.Status != core.OrderInvalid || donor.Finalized() || donor.Prep != core.PrepPrepared ||
			donor.UpstreamOrderURL == "" || donor.AdoptedByOrderID != "":
			return conflict("order %q is not adoptable (status %s, prep %s, adopted by %q)",
				donorID, donor.Status, donor.Prep, donor.AdoptedByOrderID)
		case donor.Provider != o.Provider:
			return conflict("order %q belongs to provider %q, not %q", donorID, donor.Provider, o.Provider)
		case !donor.Names.Equal(o.Names):
			return conflict("order %q is for %q, not %q", donorID, donor.Names.Key(), o.Names.Key())
		}
		// Release the donor first: the unique index on live upstream order
		// URLs is checked per statement.
		res, err := tx.ExecContext(ctx, `UPDATE orders SET adopted_by_order_id = ?, updated_at = ?
			WHERE id = ? AND `+adoptableWhere, o.ID, ts(updated), donorID)
		if err != nil {
			return err
		}
		if n, err := res.RowsAffected(); err != nil {
			return err
		} else if n != 1 {
			return conflict("order %q is not adoptable", donorID)
		}
		n := *o
		n.Prep = core.PrepPrepared
		n.UpstreamOrderURL = donor.UpstreamOrderURL
		n.UpstreamReplaces = donor.UpstreamReplaces
		n.UpstreamExpiresAt = donor.UpstreamExpiresAt
		return insertOrder(ctx, tx, &n, updated)
	})
	if err != nil {
		return err
	}
	o.Prep = core.PrepPrepared
	o.UpstreamOrderURL = donor.UpstreamOrderURL
	o.UpstreamReplaces = donor.UpstreamReplaces
	o.UpstreamExpiresAt = donor.UpstreamExpiresAt
	o.UpdatedAt = updated
	return nil
}

func (st *orderStore) Get(ctx context.Context, id string) (*core.Order, error) {
	o, err := queryOne(ctx, st.s.r, scanOrder, "order", id, `SELECT `+orderCols+` FROM orders WHERE id = ?`, id)
	return o, wrap(err)
}

func (st *orderStore) FindOpen(ctx context.Context, accountID, setKey string, now time.Time) (*core.Order, error) {
	o, err := queryOne(ctx, st.s.r, scanOrder, "open order for", setKey, `SELECT `+orderCols+` FROM orders
		WHERE account_id = ? AND set_key = ? AND mode = 'acme' AND status = 'ready' AND expires_at > ?
		ORDER BY created_at DESC, rowid DESC LIMIT 1`, accountID, setKey, ts(now))
	return o, wrap(err)
}

func (st *orderStore) FindAdoptable(ctx context.Context, provider, setKey string, now time.Time) (*core.Order, error) {
	o, err := queryOne(ctx, st.s.r, scanOrder, "adoptable order for", setKey, `SELECT `+orderCols+` FROM orders
		WHERE provider = ? AND set_key = ? AND `+adoptableWhere+`
		AND (upstream_expires_at = 0 OR upstream_expires_at > ?)
		ORDER BY created_at DESC, rowid DESC LIMIT 1`, provider, setKey, ts(now.Add(time.Hour)))
	return o, wrap(err)
}

// change loads order id inside a write transaction, lets fn decide, and
// runs the update fn returns (nil query: nothing to do).
func (st *orderStore) change(ctx context.Context, id string, fn func(o *core.Order) (query string, args []any, err error)) error {
	return st.s.write(ctx, func(tx *sql.Tx) error {
		o, err := getOrderTx(ctx, tx, id)
		if err != nil {
			return err
		}
		query, args, err := fn(o)
		if err != nil || query == "" {
			return err
		}
		_, err = tx.ExecContext(ctx, query, args...)
		return err
	})
}

func (st *orderStore) SetUpstream(ctx context.Context, id, upstreamOrderURL, upstreamReplaces string, upstreamExpires, now time.Time) error {
	if upstreamOrderURL == "" {
		return fmt.Errorf("store: order %q: empty upstream order URL", id)
	}
	return st.s.write(ctx, func(tx *sql.Tx) error {
		o, err := getOrderTx(ctx, tx, id)
		if err != nil {
			return err
		}
		if o.Prep != core.PrepIntent || (o.Status != core.OrderReady && o.Status != core.OrderProcessing) {
			return conflict("order %q: cannot record upstream order in status %s, prep %s", id, o.Status, o.Prep)
		}
		// A CA may answer newOrder with an existing pending order of the
		// same account and names (Let's Encrypt does). When that upstream
		// order belongs to an order that already failed here, hand it
		// over: the failed order is marked adopted by this one, which
		// releases the unique index on live upstream order URLs. A live
		// holder stays a conflict.
		var holder, status string
		err = tx.QueryRowContext(ctx, `SELECT id, status FROM orders
			WHERE upstream_order_url = ? AND adopted_by_order_id = '' AND id <> ?`, upstreamOrderURL, id).Scan(&holder, &status)
		switch {
		case errors.Is(err, sql.ErrNoRows):
		case err != nil:
			return err
		case core.OrderStatus(status) != core.OrderInvalid:
			return conflict("order %q: upstream order %s belongs to order %q (status %s)", id, upstreamOrderURL, holder, status)
		default:
			if _, err := tx.ExecContext(ctx, `UPDATE orders SET adopted_by_order_id = ?, updated_at = ? WHERE id = ?`,
				id, ts(now), holder); err != nil {
				return err
			}
		}
		_, err = tx.ExecContext(ctx, `UPDATE orders SET prep = 'preparing', upstream_order_url = ?, upstream_replaces = ?,
			upstream_expires_at = ?, updated_at = ? WHERE id = ?`,
			upstreamOrderURL, upstreamReplaces, ts(upstreamExpires), ts(now), id)
		return err
	})
}

func (st *orderStore) SetPrepared(ctx context.Context, id string, now time.Time) error {
	return st.change(ctx, id, func(o *core.Order) (string, []any, error) {
		switch {
		case o.Prep == core.PrepPrepared:
			return "", nil, nil
		case o.Prep != core.PrepPreparing || o.Status.Terminal():
			return "", nil, conflict("order %q: cannot mark prepared in status %s, prep %s", id, o.Status, o.Prep)
		}
		return `UPDATE orders SET prep = 'prepared', updated_at = ? WHERE id = ?`, []any{ts(now), id}, nil
	})
}

func (st *orderStore) BeginFinalize(ctx context.Context, id, csrHash string, csrDER []byte, now time.Time) (*core.Order, bool, error) {
	if csrHash == "" || len(csrDER) == 0 {
		return nil, false, fmt.Errorf("store: order %q: empty CSR", id)
	}
	var out *core.Order
	var first bool
	err := st.s.write(ctx, func(tx *sql.Tx) error {
		o, err := getOrderTx(ctx, tx, id)
		if err != nil {
			return err
		}
		switch {
		case o.Finalized() && o.CSRHash == csrHash:
			out = o
			return nil
		case o.Finalized():
			return fmt.Errorf("store: order %q: %w", id, core.ErrCSRMismatch)
		case o.Status == core.OrderInvalid:
			out = o
			return nil
		case o.Status != core.OrderReady:
			return conflict("order %q: status %s without a CSR", id, o.Status)
		case !o.ExpiresAt.After(now):
			return fmt.Errorf("store: order %q: %w", id, core.ErrExpired)
		}
		if _, err := tx.ExecContext(ctx, `UPDATE orders SET status = 'processing', csr_hash = ?, csr_der = ?,
			updated_at = ? WHERE id = ?`, csrHash, csrDER, ts(now), id); err != nil {
			return err
		}
		o.Status, o.CSRHash, o.CSRDER, o.UpdatedAt = core.OrderProcessing, csrHash, append([]byte(nil), csrDER...), tm(ts(now))
		out, first = o, true
		return nil
	})
	if err != nil {
		return nil, false, err
	}
	return out, first, nil
}

func (st *orderStore) Complete(ctx context.Context, id string, cert *core.Certificate, now time.Time) error {
	if cert == nil || cert.ID == "" {
		return fmt.Errorf("store: order %q: certificate without ID", id)
	}
	if cert.OrderID != id {
		return conflict("certificate %q belongs to order %q, not %q", cert.ID, cert.OrderID, id)
	}
	return st.s.write(ctx, func(tx *sql.Tx) error {
		o, err := getOrderTx(ctx, tx, id)
		if err != nil {
			return err
		}
		if o.Status != core.OrderProcessing {
			return conflict("order %q: cannot complete in status %s", id, o.Status)
		}
		if err := insertCertificate(ctx, tx, cert, o.Mode); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `UPDATE orders SET status = 'valid', certificate_id = ?, csr_der = NULL,
			updated_at = ? WHERE id = ?`, cert.ID, ts(now), id); err != nil {
			return err
		}
		if cert.ReplacesID != "" && cert.ReplacesID != cert.ID {
			_, err := tx.ExecContext(ctx, `UPDATE certificates SET replaced_by_id = ?
				WHERE id = ? AND replaced_by_id = ''`, cert.ID, cert.ReplacesID)
			return err
		}
		return nil
	})
}

// failSQL ends an order: status invalid, the problem recorded, the CSR
// dropped, and prep failed unless it is prepared (a prepared upstream order
// that never saw a CSR stays adoptable).
const failSQL = `UPDATE orders SET status = 'invalid', error = ?, csr_der = NULL,
	prep = CASE prep WHEN 'prepared' THEN 'prepared' ELSE 'failed' END, updated_at = ?`

func (st *orderStore) Fail(ctx context.Context, id string, problem *core.Problem, now time.Time) error {
	pj, err := problemJSON(problem)
	if err != nil {
		return fmt.Errorf("store: %w", err)
	}
	return st.change(ctx, id, func(o *core.Order) (string, []any, error) {
		switch o.Status {
		case core.OrderInvalid:
			return "", nil, nil
		case core.OrderValid:
			return "", nil, conflict("order %q is valid and cannot fail", id)
		}
		return failSQL + ` WHERE id = ?`, []any{pj, ts(now), id}, nil
	})
}

// expiredProblem is the error of an order that never received its CSR.
func expiredProblem() *core.Problem { return core.NewProblem(core.ProblemMalformed, "order expired") }

func (st *orderStore) ExpireDue(ctx context.Context, now time.Time) ([]core.Order, error) {
	pj, err := problemJSON(expiredProblem())
	if err != nil {
		return nil, fmt.Errorf("store: %w", err)
	}
	var out []*core.Order
	err = st.s.write(ctx, func(tx *sql.Tx) error {
		ids, err := queryAll(ctx, tx, func(r scanner) (string, error) {
			var id string
			return id, r.Scan(&id)
		}, `SELECT id FROM orders WHERE status = 'ready' AND expires_at <= ? ORDER BY created_at, rowid`, ts(now))
		if err != nil || len(ids) == 0 {
			return err
		}
		if _, err := tx.ExecContext(ctx, failSQL+` WHERE status = 'ready' AND expires_at <= ?`,
			pj, ts(now), ts(now)); err != nil {
			return err
		}
		for _, id := range ids {
			o, err := getOrderTx(ctx, tx, id)
			if err != nil {
				return err
			}
			out = append(out, o)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	if out == nil {
		return []core.Order{}, nil
	}
	return deref(out), nil
}

func (st *orderStore) ListActive(ctx context.Context) ([]core.Order, error) {
	list, err := queryAll(ctx, st.s.r, scanOrder, `SELECT `+orderCols+` FROM orders
		WHERE status IN ('ready', 'processing') ORDER BY created_at, rowid`)
	return deref(list), wrap(err)
}

func (st *orderStore) List(ctx context.Context, f core.OrderFilter) ([]core.Order, error) {
	q := `SELECT ` + orderCols + ` FROM orders WHERE 1 = 1`
	var args []any
	if f.Mode != "" {
		q += ` AND mode = ?`
		args = append(args, string(f.Mode))
	}
	if f.Status != "" {
		q += ` AND status = ?`
		args = append(args, string(f.Status))
	}
	if f.Provider != "" {
		q += ` AND provider = ?`
		args = append(args, f.Provider)
	}
	if f.NameContains != "" {
		q += ` AND instr(set_key, ?) > 0`
		args = append(args, f.NameContains)
	}
	q += ` ORDER BY created_at DESC, rowid DESC LIMIT ? OFFSET ?`
	args = append(args, limit(f.Limit), max(f.Offset, 0))
	list, err := queryAll(ctx, st.s.r, scanOrder, q, args...)
	return deref(list), wrap(err)
}

func limit(n int) int {
	if n <= 0 {
		return 100
	}
	return n
}

func (st *orderStore) Prune(ctx context.Context, before time.Time) (int, error) {
	return execCount(ctx, st.s, `DELETE FROM orders
		WHERE status IN ('valid', 'invalid') AND updated_at < ?
		AND NOT EXISTS (SELECT 1 FROM orders a WHERE a.id = orders.adopted_by_order_id
			AND a.status IN ('ready', 'processing'))`, ts(before))
}
