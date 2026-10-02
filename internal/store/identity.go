package store

import (
	"context"
	"database/sql"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net/netip"
	"strconv"
	"time"

	"tls-broker/internal/core"
)

var (
	_ core.UserStore    = (*userStore)(nil)
	_ core.GrantStore   = (*grantStore)(nil)
	_ core.SessionStore = (*sessionStore)(nil)
	_ core.AccountStore = (*accountStore)(nil)
)

// ---------------------------------------------------------------------------
// Users
// ---------------------------------------------------------------------------

type userStore struct{ s *Store }

const userCols = `id, username, local, role, blocked, created_at, last_login_at`

func scanUser(r scanner) (*core.User, error) {
	var u core.User
	var role string
	var created, login int64
	if err := r.Scan(&u.ID, &u.Username, &u.Local, &role, &u.Blocked, &created, &login); err != nil {
		return nil, err
	}
	u.Role = core.Role(role)
	u.CreatedAt, u.LastLoginAt = tm(created), tm(login)
	return &u, nil
}

func (st *userStore) Ensure(ctx context.Context, username string, local bool, now time.Time) (*core.User, bool, error) {
	var u *core.User
	var created bool
	err := st.s.write(ctx, func(tx *sql.Tx) error {
		res, err := tx.ExecContext(ctx, `INSERT INTO users (username, local, role, blocked, created_at)
			VALUES (?, ?, 'normal', 0, ?) ON CONFLICT (username, local) DO NOTHING`,
			username, b2i(local), ts(now))
		if err != nil {
			return err
		}
		n, err := res.RowsAffected()
		if err != nil {
			return err
		}
		created = n == 1
		u, err = queryOne(ctx, tx, scanUser, "user", username,
			`SELECT `+userCols+` FROM users WHERE username = ? AND local = ?`, username, b2i(local))
		return err
	})
	if err != nil {
		return nil, false, err
	}
	return u, created, nil
}

func (st *userStore) Get(ctx context.Context, id int64) (*core.User, error) {
	u, err := queryOne(ctx, st.s.r, scanUser, "user", strconv.FormatInt(id, 10),
		`SELECT `+userCols+` FROM users WHERE id = ?`, id)
	return u, wrap(err)
}

func (st *userStore) GetByUsername(ctx context.Context, username string, local bool) (*core.User, error) {
	u, err := queryOne(ctx, st.s.r, scanUser, "user", username,
		`SELECT `+userCols+` FROM users WHERE username = ? AND local = ?`, username, b2i(local))
	return u, wrap(err)
}

func (st *userStore) List(ctx context.Context) ([]core.User, error) {
	us, err := queryAll(ctx, st.s.r, scanUser, `SELECT `+userCols+` FROM users ORDER BY username, local`)
	return deref(us), wrap(err)
}

func (st *userStore) SetRole(ctx context.Context, id int64, role core.Role) error {
	if !role.Valid() {
		return fmt.Errorf("store: invalid role %q", role)
	}
	return st.update(ctx, id, `UPDATE users SET role = ? WHERE id = ?`, string(role), id)
}

func (st *userStore) SetBlocked(ctx context.Context, id int64, blocked bool) error {
	return st.update(ctx, id, `UPDATE users SET blocked = ? WHERE id = ?`, b2i(blocked), id)
}

func (st *userStore) TouchLogin(ctx context.Context, id int64, at time.Time) error {
	return st.update(ctx, id, `UPDATE users SET last_login_at = ? WHERE id = ?`, ts(at), id)
}

func (st *userStore) update(ctx context.Context, id int64, query string, args ...any) error {
	return st.s.write(ctx, func(tx *sql.Tx) error {
		res, err := tx.ExecContext(ctx, query, args...)
		if err != nil {
			return err
		}
		return mustAffect(res, "user", strconv.FormatInt(id, 10))
	})
}

// deref turns a slice of pointers into a slice of values.
func deref[T any](in []*T) []T {
	if in == nil {
		return nil
	}
	out := make([]T, len(in))
	for i, p := range in {
		out[i] = *p
	}
	return out
}

// ---------------------------------------------------------------------------
// Grants
// ---------------------------------------------------------------------------

type grantStore struct{ s *Store }

const grantCols = `id, owner_user_id, prefix, enabled, wildcard, note, created_at`

func scanGrant(r scanner) (*core.Grant, error) {
	var g core.Grant
	var prefix string
	var created int64
	if err := r.Scan(&g.ID, &g.OwnerUserID, &prefix, &g.Enabled, &g.Wildcard, &g.Note, &created); err != nil {
		return nil, err
	}
	p, err := netip.ParsePrefix(prefix)
	if err != nil {
		return nil, fmt.Errorf("stored grant prefix %q: %w", prefix, err)
	}
	g.Prefix, g.CreatedAt = p, tm(created)
	return &g, nil
}

// ipv4Num returns the address as a big-endian integer.
func ipv4Num(a netip.Addr) int64 {
	b := a.As4()
	return int64(binary.BigEndian.Uint32(b[:]))
}

func (st *grantStore) Create(ctx context.Context, g *core.Grant) error {
	if !g.Prefix.IsValid() || !g.Prefix.Addr().Is4() {
		return fmt.Errorf("store: grant prefix %q is not a valid IPv4 prefix", g.Prefix)
	}
	p := g.Prefix.Masked()
	start := ipv4Num(p.Addr())
	end := start | int64(uint32(0xffffffff)>>p.Bits()) // shift by 32 gives 0
	var id int64
	err := st.s.write(ctx, func(tx *sql.Tx) error {
		res, err := tx.ExecContext(ctx, `INSERT INTO grants
			(owner_user_id, prefix, net_start, net_end, bits, enabled, wildcard, note, created_at)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			g.OwnerUserID, p.String(), start, end, p.Bits(), b2i(g.Enabled), b2i(g.Wildcard), g.Note, ts(g.CreatedAt))
		if err != nil {
			return err
		}
		id, err = res.LastInsertId()
		return err
	})
	if err != nil {
		return err
	}
	g.ID = id
	g.Prefix = p
	return nil
}

func (st *grantStore) Get(ctx context.Context, id int64) (*core.Grant, error) {
	g, err := queryOne(ctx, st.s.r, scanGrant, "grant", strconv.FormatInt(id, 10),
		`SELECT `+grantCols+` FROM grants WHERE id = ?`, id)
	return g, wrap(err)
}

func (st *grantStore) List(ctx context.Context, ownerUserID int64) ([]core.Grant, error) {
	var gs []*core.Grant
	var err error
	if ownerUserID == 0 {
		gs, err = queryAll(ctx, st.s.r, scanGrant, `SELECT `+grantCols+` FROM grants ORDER BY id`)
	} else {
		gs, err = queryAll(ctx, st.s.r, scanGrant,
			`SELECT `+grantCols+` FROM grants WHERE owner_user_id = ? ORDER BY id`, ownerUserID)
	}
	return deref(gs), wrap(err)
}

func (st *grantStore) Update(ctx context.Context, g *core.Grant) error {
	return st.s.write(ctx, func(tx *sql.Tx) error {
		res, err := tx.ExecContext(ctx, `UPDATE grants SET enabled = ?, wildcard = ?, note = ?, owner_user_id = ?
			WHERE id = ?`, b2i(g.Enabled), b2i(g.Wildcard), g.Note, g.OwnerUserID, g.ID)
		if err != nil {
			return err
		}
		return mustAffect(res, "grant", strconv.FormatInt(g.ID, 10))
	})
}

func (st *grantStore) Delete(ctx context.Context, id int64) error {
	return st.s.write(ctx, func(tx *sql.Tx) error {
		res, err := tx.ExecContext(ctx, `DELETE FROM grants WHERE id = ?`, id)
		if err != nil {
			return err
		}
		return mustAffect(res, "grant", strconv.FormatInt(id, 10))
	})
}

func (st *grantStore) Match(ctx context.Context, addr netip.Addr) ([]core.Grant, error) {
	if !addr.Is4() {
		return []core.Grant{}, nil
	}
	n := ipv4Num(addr)
	gs, err := queryAll(ctx, st.s.r, scanGrant, `SELECT `+grantCols+` FROM grants
		WHERE enabled = 1 AND net_start <= ? AND net_end >= ?
		ORDER BY wildcard DESC, bits DESC, id`, n, n)
	return deref(gs), wrap(err)
}

// ---------------------------------------------------------------------------
// Sessions
// ---------------------------------------------------------------------------

type sessionStore struct{ s *Store }

const sessionCols = `token_hash, user_id, csrf_token, source_ip, created_at, expires_at, last_seen_at`

func scanSession(r scanner) (*core.Session, error) {
	var s core.Session
	var ip string
	var created, expires, seen int64
	if err := r.Scan(&s.TokenHash, &s.UserID, &s.CSRFToken, &ip, &created, &expires, &seen); err != nil {
		return nil, err
	}
	a, err := parseAddr(ip)
	if err != nil {
		return nil, fmt.Errorf("stored session address %q: %w", ip, err)
	}
	s.SourceIP = a
	s.CreatedAt, s.ExpiresAt, s.LastSeenAt = tm(created), tm(expires), tm(seen)
	return &s, nil
}

func (st *sessionStore) Create(ctx context.Context, s *core.Session) error {
	if s.TokenHash == "" {
		return fmt.Errorf("store: session without token hash")
	}
	return st.s.write(ctx, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, `INSERT INTO sessions (`+sessionCols+`) VALUES (?, ?, ?, ?, ?, ?, ?)`,
			s.TokenHash, s.UserID, s.CSRFToken, addrText(s.SourceIP), ts(s.CreatedAt), ts(s.ExpiresAt), ts(s.LastSeenAt))
		return err
	})
}

func (st *sessionStore) Get(ctx context.Context, tokenHash string) (*core.Session, error) {
	s, err := queryOne(ctx, st.s.r, scanSession, "session", "…",
		`SELECT `+sessionCols+` FROM sessions WHERE token_hash = ?`, tokenHash)
	return s, wrap(err)
}

func (st *sessionStore) Touch(ctx context.Context, tokenHash string, at time.Time) error {
	return st.s.write(ctx, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, `UPDATE sessions SET last_seen_at = ? WHERE token_hash = ?`, ts(at), tokenHash)
		return err
	})
}

func (st *sessionStore) Delete(ctx context.Context, tokenHash string) error {
	return st.s.write(ctx, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, `DELETE FROM sessions WHERE token_hash = ?`, tokenHash)
		return err
	})
}

func (st *sessionStore) DeleteByUser(ctx context.Context, userID int64) (int, error) {
	return st.deleteWhere(ctx, `DELETE FROM sessions WHERE user_id = ?`, userID)
}

func (st *sessionStore) DeleteExpired(ctx context.Context, now time.Time) (int, error) {
	return st.deleteWhere(ctx, `DELETE FROM sessions WHERE expires_at <= ?`, ts(now))
}

func (st *sessionStore) deleteWhere(ctx context.Context, query string, args ...any) (int, error) {
	return execCount(ctx, st.s, query, args...)
}

// execCount runs one statement in a write transaction and returns the number
// of rows it changed.
func execCount(ctx context.Context, s *Store, query string, args ...any) (int, error) {
	var n int64
	err := s.write(ctx, func(tx *sql.Tx) error {
		res, err := tx.ExecContext(ctx, query, args...)
		if err != nil {
			return err
		}
		n, err = res.RowsAffected()
		return err
	})
	return int(n), err
}

// ---------------------------------------------------------------------------
// Downstream ACME accounts
// ---------------------------------------------------------------------------

type accountStore struct{ s *Store }

const accountCols = `id, thumbprint, jwk, status, contact, created_at`

func scanAccount(r scanner) (*core.ACMEAccount, error) {
	var a core.ACMEAccount
	var status, contact string
	var created int64
	if err := r.Scan(&a.ID, &a.Thumbprint, &a.JWK, &status, &contact, &created); err != nil {
		return nil, err
	}
	a.Status, a.CreatedAt = core.AccountStatus(status), tm(created)
	if err := json.Unmarshal([]byte(contact), &a.Contact); err != nil {
		return nil, fmt.Errorf("stored account contact: %w", err)
	}
	if len(a.Contact) == 0 {
		a.Contact = nil
	}
	return &a, nil
}

func contactJSON(c []string) (string, error) {
	if c == nil {
		c = []string{}
	}
	b, err := json.Marshal(c)
	return string(b), err
}

func (st *accountStore) Create(ctx context.Context, a *core.ACMEAccount) error {
	contact, err := contactJSON(a.Contact)
	if err != nil {
		return fmt.Errorf("store: %w", err)
	}
	if a.JWK == nil {
		return fmt.Errorf("store: account %q without JWK", a.ID)
	}
	return st.s.write(ctx, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, `INSERT INTO acme_accounts (`+accountCols+`) VALUES (?, ?, ?, ?, ?, ?)`,
			a.ID, a.Thumbprint, a.JWK, string(a.Status), contact, ts(a.CreatedAt))
		return err
	})
}

func (st *accountStore) Get(ctx context.Context, id string) (*core.ACMEAccount, error) {
	a, err := queryOne(ctx, st.s.r, scanAccount, "account", id,
		`SELECT `+accountCols+` FROM acme_accounts WHERE id = ?`, id)
	return a, wrap(err)
}

func (st *accountStore) GetByThumbprint(ctx context.Context, thumbprint string) (*core.ACMEAccount, error) {
	a, err := queryOne(ctx, st.s.r, scanAccount, "account with thumbprint", thumbprint,
		`SELECT `+accountCols+` FROM acme_accounts WHERE thumbprint = ?`, thumbprint)
	return a, wrap(err)
}

func (st *accountStore) Update(ctx context.Context, a *core.ACMEAccount) error {
	contact, err := contactJSON(a.Contact)
	if err != nil {
		return fmt.Errorf("store: %w", err)
	}
	return st.s.write(ctx, func(tx *sql.Tx) error {
		res, err := tx.ExecContext(ctx, `UPDATE acme_accounts SET contact = ?, status = ? WHERE id = ?`,
			contact, string(a.Status), a.ID)
		if err != nil {
			return err
		}
		return mustAffect(res, "account", a.ID)
	})
}

func (st *accountStore) UpdateKey(ctx context.Context, id string, jwk []byte, thumbprint string) error {
	if jwk == nil {
		return fmt.Errorf("store: account %q: empty JWK", id)
	}
	return st.s.write(ctx, func(tx *sql.Tx) error {
		res, err := tx.ExecContext(ctx, `UPDATE acme_accounts SET jwk = ?, thumbprint = ? WHERE id = ?`,
			jwk, thumbprint, id)
		if err != nil {
			return err
		}
		return mustAffect(res, "account", id)
	})
}
