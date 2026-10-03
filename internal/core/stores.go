package core

import (
	"context"
	"net/netip"
	"time"
)

// The store interfaces below are all implemented by internal/store on one
// SQLite database. See the package comment for the conventions they share
// (ErrNotFound, ErrConflict, one transaction per method, explicit time
// arguments, fresh copies).

// UserStore holds users, roles and the blocked flag.
type UserStore interface {
	// Ensure returns the user (username, local), creating it with role
	// normal, not blocked, CreatedAt=now when it does not exist. created
	// reports whether it was created.
	Ensure(ctx context.Context, username string, local bool, now time.Time) (u *User, created bool, err error)
	// Get returns a user by ID.
	Get(ctx context.Context, id int64) (*User, error)
	// GetByUsername returns the user (username, local).
	GetByUsername(ctx context.Context, username string, local bool) (*User, error)
	// List returns all users ordered by username, LDAP users before the
	// local one of the same name.
	List(ctx context.Context) ([]User, error)
	// SetRole changes the role. ErrNotFound if the user does not exist.
	SetRole(ctx context.Context, id int64, role Role) error
	// SetBlocked changes the blocked flag. ErrNotFound if the user does
	// not exist.
	SetBlocked(ctx context.Context, id int64, blocked bool) error
	// TouchLogin sets LastLoginAt.
	TouchLogin(ctx context.Context, id int64, at time.Time) error
}

// GrantStore holds IP grants.
type GrantStore interface {
	// Create inserts the grant and sets g.ID. g.Prefix must be a valid
	// IPv4 prefix; it is stored masked. Several grants may cover the same
	// prefix.
	Create(ctx context.Context, g *Grant) error
	// Get returns a grant by ID.
	Get(ctx context.Context, id int64) (*Grant, error)
	// List returns grants ordered by ID. ownerUserID 0 lists all, any
	// other value only that owner's.
	List(ctx context.Context, ownerUserID int64) ([]Grant, error)
	// Update saves Enabled, Wildcard, Note and OwnerUserID of the grant
	// with g.ID. Prefix and CreatedAt are immutable. ErrNotFound if it
	// does not exist.
	Update(ctx context.Context, g *Grant) error
	// Delete removes a grant. ErrNotFound if it does not exist.
	Delete(ctx context.Context, id int64) error
	// Match returns the enabled grants whose prefix contains addr,
	// ordered: wildcard grants first, then longer prefixes first, then
	// lower ID. An address that is not IPv4 matches nothing.
	Match(ctx context.Context, addr netip.Addr) ([]Grant, error)
}

// SessionStore holds UI sessions by token hash.
type SessionStore interface {
	// Create inserts the session. ErrConflict if TokenHash exists.
	Create(ctx context.Context, s *Session) error
	// Get returns the session whether or not it has expired; the caller
	// compares ExpiresAt with its clock.
	Get(ctx context.Context, tokenHash string) (*Session, error)
	// Touch sets LastSeenAt; a missing session is not an error.
	Touch(ctx context.Context, tokenHash string, at time.Time) error
	// Delete removes the session; a missing session is not an error.
	Delete(ctx context.Context, tokenHash string) error
	// DeleteByUser removes every session of the user and returns how many.
	DeleteByUser(ctx context.Context, userID int64) (int, error)
	// DeleteExpired removes sessions with ExpiresAt <= now and returns how
	// many.
	DeleteExpired(ctx context.Context, now time.Time) (int, error)
}

// AccountStore holds downstream ACME accounts.
type AccountStore interface {
	// Create inserts the account. ErrConflict if the ID or the thumbprint
	// exists (the caller then returns the existing account, RFC 8555
	// §7.3.1).
	Create(ctx context.Context, a *ACMEAccount) error
	// Get returns an account by ID.
	Get(ctx context.Context, id string) (*ACMEAccount, error)
	// GetByThumbprint returns the account with that key thumbprint.
	GetByThumbprint(ctx context.Context, thumbprint string) (*ACMEAccount, error)
	// Update saves Contact and Status. ErrNotFound if it does not exist.
	Update(ctx context.Context, a *ACMEAccount) error
	// UpdateKey replaces the account key (keyChange). ErrConflict if
	// another account has the new thumbprint; ErrNotFound if the account
	// does not exist.
	UpdateKey(ctx context.Context, id string, jwk []byte, thumbprint string) error
}

// OrderFilter selects orders for listing.
type OrderFilter struct {
	Mode     Mode        // "" for any
	Status   OrderStatus // "" for any
	Provider string      // "" for any
	// NameContains matches a substring of the identifier-set key.
	NameContains string
	Limit        int // 0 means 100
	Offset       int
}

// OrderStore holds broker orders and enforces the state rules that make
// issuance idempotent and crash-safe. Every method that changes an order
// sets UpdatedAt to its `now`.
type OrderStore interface {
	// Create inserts a new order. The caller sets every field; Status
	// must be ready and Prep intent. ErrConflict if the ID exists.
	Create(ctx context.Context, o *Order) error
	// CreateAdopting inserts the new order o and, atomically, hands it
	// the upstream order of the donor order: o gets the donor's
	// UpstreamOrderURL, UpstreamReplaces and UpstreamExpiresAt and
	// Prep=prepared (the fields are also set on *o), and the donor gets
	// AdoptedByOrderID=o.ID. o.Provider must equal the donor's provider.
	//
	// ErrConflict, with nothing changed, unless the donor is adoptable:
	// Status invalid, no CSR recorded, Prep prepared, UpstreamOrderURL
	// set, not yet adopted. ErrNotFound if the donor does not exist.
	// This is what guarantees that an upstream order serves at most one
	// live order.
	CreateAdopting(ctx context.Context, o *Order, donorID string) error
	// Get returns an order by ID.
	Get(ctx context.Context, id string) (*Order, error)
	// FindOpen returns the newest order of that account and
	// identifier-set key that is still waiting for its CSR: Mode acme,
	// Status ready, ExpiresAt > now. ErrNotFound if there is none.
	FindOpen(ctx context.Context, accountID, setKey string, now time.Time) (*Order, error)
	// FindAdoptable returns the newest adoptable order (see
	// CreateAdopting) for that provider and identifier-set key whose
	// upstream order is still usable: UpstreamExpiresAt is zero or after
	// now+1h. Orders of either mode qualify. ErrNotFound if there is
	// none. Run ExpireDue first so freshly expired orders are seen.
	FindAdoptable(ctx context.Context, provider, setKey string, now time.Time) (*Order, error)
	// SetUpstream records the upstream order right after it was created:
	// Prep intent -> preparing, UpstreamOrderURL, UpstreamReplaces,
	// UpstreamExpiresAt. ErrConflict unless Prep is intent and Status is
	// ready or processing. A CA may return an existing pending order for
	// the same account and names: when the URL is held by an invalid order
	// (not adopted), that order gets AdoptedByOrderID=id in the same
	// transaction and the URL moves to id; any other holder is
	// ErrConflict, with nothing changed.
	SetUpstream(ctx context.Context, id, upstreamOrderURL, upstreamReplaces string, upstreamExpires, now time.Time) error
	// SetPrepared marks preparation finished: Prep preparing -> prepared.
	// Calling it on an order that is already prepared is a no-op.
	// ErrConflict for any other Prep or a terminal Status.
	SetPrepared(ctx context.Context, id string, now time.Time) error
	// BeginFinalize records the CSR, exactly once per order.
	//
	//   - Status ready, ExpiresAt > now: stores csrHash and csrDER, sets
	//     Status processing; returns the order and first=true.
	//   - A CSR is already recorded and csrHash equals it: changes
	//     nothing; returns the order as it is (processing, valid or
	//     invalid) and first=false.
	//   - A CSR is already recorded and csrHash differs: ErrCSRMismatch.
	//   - Status ready but ExpiresAt <= now: ErrExpired.
	//   - Status invalid with no CSR recorded: returns the order and
	//     first=false (the caller reports Order.Error).
	BeginFinalize(ctx context.Context, id, csrHash string, csrDER []byte, now time.Time) (o *Order, first bool, err error)
	// Complete stores the issued certificate and finishes the order in
	// one transaction: inserts cert (cert.OrderID must be id; for Mode
	// direct the chain is not stored), sets Status valid and
	// CertificateID, clears CSRDER, and, when cert.ReplacesID is set and
	// that certificate has no ReplacedByID yet, sets its ReplacedByID to
	// cert.ID. ErrConflict unless Status is processing; also when the
	// certificate ID or ARICertID already exists.
	Complete(ctx context.Context, id string, cert *Certificate, now time.Time) error
	// Fail ends the order: Status invalid, Error=problem, CSRDER cleared,
	// and Prep failed unless Prep is prepared (a prepared, never
	// finalized upstream order stays adoptable). Failing an order that
	// is already invalid is a no-op; failing a valid order is
	// ErrConflict.
	Fail(ctx context.Context, id string, problem *Problem, now time.Time) error
	// ExpireDue ends every order with Status ready and ExpiresAt <= now
	// like Fail does, with a "malformed: order expired" problem, and
	// returns the orders it changed (after the change) so the caller can
	// refund reservations and clean up DNS.
	ExpireDue(ctx context.Context, now time.Time) ([]Order, error)
	// ListActive returns every order whose Status is ready or processing,
	// oldest first: the input of startup recovery.
	ListActive(ctx context.Context) ([]Order, error)
	// List returns orders matching the filter, newest first.
	List(ctx context.Context, f OrderFilter) ([]Order, error)
	// Prune deletes terminal orders with UpdatedAt < before that are not
	// referenced as AdoptedByOrderID donor of a non-terminal order, and
	// returns how many. Certificates are kept.
	Prune(ctx context.Context, before time.Time) (int, error)
}

// CertificateFilter selects certificates for listing.
type CertificateFilter struct {
	Mode     Mode   // "" for any
	Provider string // "" for any
	// NameContains matches a substring of the identifier-set key.
	NameContains string
	// ValidAt, when non-zero, keeps certificates with NotAfter > ValidAt.
	ValidAt time.Time
	Limit   int // 0 means 100
	Offset  int
}

// CertificateStore reads the certificate mapping (architecture §8).
// Certificates are created only through OrderStore.Complete.
type CertificateStore interface {
	// Get returns a certificate by ID.
	Get(ctx context.Context, id string) (*Certificate, error)
	// GetByARICertID returns the certificate with that ARI identifier.
	GetByARICertID(ctx context.Context, ariCertID string) (*Certificate, error)
	// Newest returns the certificate with the latest NotBefore (ties: the
	// latest IssuedAt) for an identifier-set key, expired or not, replaced
	// or not. provider "" means any provider. ErrNotFound if none.
	Newest(ctx context.Context, setKey, provider string) (*Certificate, error)
	// NewestUnreplaced is Newest restricted to certificates that have no
	// ReplacedByID and NotAfter > now: the predecessor to name in
	// `replaces`. provider must be given.
	NewestUnreplaced(ctx context.Context, setKey, provider string, now time.Time) (*Certificate, error)
	// MarkReplaced sets ReplacedByID of certificate id to byID when it is
	// still empty; when already set it changes nothing and returns nil.
	// ErrNotFound if id does not exist.
	MarkReplaced(ctx context.Context, id, byID string) error
	// List returns certificates matching the filter, newest NotBefore
	// first, without ChainPEM.
	List(ctx context.Context, f CertificateFilter) ([]Certificate, error)
	// DropChains clears ChainPEM of certificates with NotAfter < before
	// (metadata is kept forever) and returns how many.
	DropChains(ctx context.Context, before time.Time) (int, error)
}

// LineageStore tracks request intervals per identifier-set key.
type LineageStore interface {
	// Get returns the lineage; ErrNotFound if nothing was observed yet.
	Get(ctx context.Context, key string) (*Lineage, error)
	// Observe atomically loads the lineage (zero Lineage with that Key
	// when absent), applies Lineage.Observe(at), saves and returns the
	// result.
	Observe(ctx context.Context, key string, at time.Time) (Lineage, error)
}

// ChallengeStore holds DNS-01 challenge rows. Only the DNS engine writes;
// the DNS proxy and the UI read.
type ChallengeStore interface {
	// Create inserts a challenge. ErrConflict if the ID exists.
	Create(ctx context.Context, c *Challenge) error
	// Get returns a challenge by ID.
	Get(ctx context.Context, id string) (*Challenge, error)
	// SetState sets State, Error (errText, may be empty) and
	// UpdatedAt=now. Any transition is allowed except out of a terminal
	// state, which is ErrConflict. ErrNotFound if it does not exist.
	SetState(ctx context.Context, id string, state ChallengeState, errText string, now time.Time) error
	// FindActive returns the non-terminal challenge with exactly that
	// owner, record name and value; ErrNotFound if none.
	FindActive(ctx context.Context, owner, recordName, value string) (*Challenge, error)
	// ListActive returns all non-terminal challenges, oldest first.
	ListActive(ctx context.Context) ([]Challenge, error)
	// ListByRecord returns the non-terminal challenges of one record name
	// in one zone, oldest first.
	ListByRecord(ctx context.Context, zoneID, recordName string) ([]Challenge, error)
	// ListByOwner returns the non-terminal challenges of an owner, oldest
	// first.
	ListByOwner(ctx context.Context, owner string) ([]Challenge, error)
	// CountCreatedSince counts challenges (any state) of an owner with
	// CreatedAt >= since; used to rate-limit DNS-proxy presents.
	CountCreatedSince(ctx context.Context, owner string, since time.Time) (int, error)
	// ListStale returns non-terminal challenges with CreatedAt < before,
	// oldest first, so abandoned values can be removed.
	ListStale(ctx context.Context, before time.Time) ([]Challenge, error)
	// Prune deletes terminal challenges with UpdatedAt < before and
	// returns how many.
	Prune(ctx context.Context, before time.Time) (int, error)
}

// DirectStore holds direct-cache metadata.
type DirectStore interface {
	// Get returns the entry of an identifier.
	Get(ctx context.Context, identifier string) (*DirectEntry, error)
	// Put creates or replaces the entry (all fields except LastFetchAt
	// and LastFetchIP, which only TouchFetch changes once the row exists;
	// on creation they are stored as given). CreatedAt is kept from the
	// existing row.
	Put(ctx context.Context, e *DirectEntry) error
	// TouchFetch sets LastFetchAt and LastFetchIP. ErrNotFound if there
	// is no entry.
	TouchFetch(ctx context.Context, identifier string, at time.Time, src netip.Addr) error
	// List returns all entries ordered by identifier.
	List(ctx context.Context) ([]DirectEntry, error)
	// Delete removes the entry; a missing entry is not an error.
	Delete(ctx context.Context, identifier string) error
}

// ProviderStateStore persists provider circuit state across restarts.
type ProviderStateStore interface {
	// Get returns the state; ErrNotFound if none was ever saved (the
	// provider is then healthy).
	Get(ctx context.Context, name string) (*ProviderState, error)
	// Put creates or replaces the state of s.Name.
	Put(ctx context.Context, s *ProviderState) error
	// List returns all saved states ordered by name.
	List(ctx context.Context) ([]ProviderState, error)
}

// BudgetStore persists the sliding-window budget events of the scheduler.
// The scheduler is the only writer; it keeps its working state in memory and
// uses the store to survive restarts.
type BudgetStore interface {
	// Reserve inserts the events atomically (all or none) in state
	// reserved and sets their IDs. All events of one call share one Ref.
	Reserve(ctx context.Context, events []BudgetEvent) error
	// Commit turns the reserved events of ref with one of the given kinds
	// into committed ones. No kinds means every kind. Events already
	// committed are left alone; no matching events is not an error.
	Commit(ctx context.Context, ref string, kinds ...BudgetKind) error
	// Release deletes the reserved events of ref with one of the given
	// kinds. No kinds means every kind. Committed events are never
	// deleted by Release.
	Release(ctx context.Context, ref string, kinds ...BudgetKind) error
	// ListByRef returns the events of ref (both states), ordered by ID.
	ListByRef(ctx context.Context, ref string) ([]BudgetEvent, error)
	// ListSince returns every event with At >= since (both states),
	// ordered by At then ID: what the scheduler loads at startup.
	ListSince(ctx context.Context, since time.Time) ([]BudgetEvent, error)
	// ListReserved returns every event in state reserved, whatever its
	// age, ordered by ID.
	ListReserved(ctx context.Context) ([]BudgetEvent, error)
	// Prune deletes committed events with At < before and returns how
	// many. Reserved events are never pruned.
	Prune(ctx context.Context, before time.Time) (int, error)
}
