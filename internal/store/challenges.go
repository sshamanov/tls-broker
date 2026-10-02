package store

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"tls-broker/internal/core"
)

var _ core.ChallengeStore = (*challengeStore)(nil)

type challengeStore struct{ s *Store }

const challengeCols = `id, zone_id, record_name, value, owner, state, error, created_at, updated_at`

// activeWhere selects non-terminal challenges.
const activeWhere = `state NOT IN ('done', 'failed')`

func scanChallenge(r scanner) (*core.Challenge, error) {
	var c core.Challenge
	var state string
	var created, updated int64
	if err := r.Scan(&c.ID, &c.ZoneID, &c.RecordName, &c.Value, &c.Owner, &state, &c.Error, &created, &updated); err != nil {
		return nil, err
	}
	c.State, c.CreatedAt, c.UpdatedAt = core.ChallengeState(state), tm(created), tm(updated)
	return &c, nil
}

func validChallengeState(s core.ChallengeState) bool {
	return s.WantsRecord() || s == core.ChallengeCleaning || s.Terminal()
}

func (st *challengeStore) Create(ctx context.Context, c *core.Challenge) error {
	if c.ID == "" {
		return fmt.Errorf("store: challenge without ID")
	}
	if !validChallengeState(c.State) {
		return fmt.Errorf("store: challenge %q: invalid state %q", c.ID, c.State)
	}
	updated := c.UpdatedAt
	if updated.IsZero() {
		updated = c.CreatedAt
	}
	return st.s.write(ctx, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, `INSERT INTO challenges (`+challengeCols+`) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			c.ID, c.ZoneID, c.RecordName, c.Value, c.Owner, string(c.State), c.Error, ts(c.CreatedAt), ts(updated))
		return err
	})
}

func (st *challengeStore) Get(ctx context.Context, id string) (*core.Challenge, error) {
	c, err := queryOne(ctx, st.s.r, scanChallenge, "challenge", id,
		`SELECT `+challengeCols+` FROM challenges WHERE id = ?`, id)
	return c, wrap(err)
}

func (st *challengeStore) SetState(ctx context.Context, id string, state core.ChallengeState, errText string, now time.Time) error {
	if !validChallengeState(state) {
		return fmt.Errorf("store: challenge %q: invalid state %q", id, state)
	}
	return st.s.write(ctx, func(tx *sql.Tx) error {
		var cur string
		if err := tx.QueryRowContext(ctx, `SELECT state FROM challenges WHERE id = ?`, id).Scan(&cur); err == sql.ErrNoRows {
			return notFound("challenge", id)
		} else if err != nil {
			return err
		}
		if cs := core.ChallengeState(cur); cs.Terminal() {
			if cs == state {
				return nil // repeating the terminal state changes nothing
			}
			return conflict("challenge %q is %s", id, cs)
		}
		_, err := tx.ExecContext(ctx, `UPDATE challenges SET state = ?, error = ?, updated_at = ? WHERE id = ?`,
			string(state), errText, ts(now), id)
		return err
	})
}

func (st *challengeStore) FindActive(ctx context.Context, owner, recordName, value string) (*core.Challenge, error) {
	c, err := queryOne(ctx, st.s.r, scanChallenge, "active challenge at", recordName,
		`SELECT `+challengeCols+` FROM challenges
		WHERE owner = ? AND record_name = ? AND value = ? AND `+activeWhere+`
		ORDER BY created_at, rowid LIMIT 1`, owner, recordName, value)
	return c, wrap(err)
}

func (st *challengeStore) list(ctx context.Context, where string, args ...any) ([]core.Challenge, error) {
	list, err := queryAll(ctx, st.s.r, scanChallenge, `SELECT `+challengeCols+` FROM challenges
		WHERE `+where+` ORDER BY created_at, rowid`, args...)
	return deref(list), wrap(err)
}

func (st *challengeStore) ListActive(ctx context.Context) ([]core.Challenge, error) {
	return st.list(ctx, activeWhere)
}

func (st *challengeStore) ListByRecord(ctx context.Context, zoneID, recordName string) ([]core.Challenge, error) {
	return st.list(ctx, `zone_id = ? AND record_name = ? AND `+activeWhere, zoneID, recordName)
}

func (st *challengeStore) ListByOwner(ctx context.Context, owner string) ([]core.Challenge, error) {
	return st.list(ctx, `owner = ? AND `+activeWhere, owner)
}

func (st *challengeStore) CountCreatedSince(ctx context.Context, owner string, since time.Time) (int, error) {
	var n int
	err := st.s.r.QueryRowContext(ctx, `SELECT count(*) FROM challenges WHERE owner = ? AND created_at >= ?`,
		owner, ts(since)).Scan(&n)
	return n, wrap(err)
}

func (st *challengeStore) ListStale(ctx context.Context, before time.Time) ([]core.Challenge, error) {
	return st.list(ctx, `created_at < ? AND `+activeWhere, ts(before))
}

func (st *challengeStore) Prune(ctx context.Context, before time.Time) (int, error) {
	return execCount(ctx, st.s, `DELETE FROM challenges WHERE state IN ('done', 'failed') AND updated_at < ?`, ts(before))
}
