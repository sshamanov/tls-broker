package core

import (
	"context"
	"net/netip"
	"time"

	"tls-broker/internal/names"
)

// ---------------------------------------------------------------------------
// Public DNS view
// ---------------------------------------------------------------------------

// CAA is one CAA resource record.
type CAA struct {
	Flag  uint8
	Tag   string // "issue", "issuewild", "iodef", ...; lower case
	Value string // unquoted, for example `letsencrypt.org; accounturi=https://...`
}

// Resolver is the broker's view of public DNS (DoH, architecture §16). There
// is no caching: every call asks the network.
//
// For all three methods a name that does not exist (NXDOMAIN) or has no
// records of the type returns an empty result and a nil error. An error
// means the answer is unknown: every resolver failed (it matches
// ErrResolver), the CNAME chain looped or was too long (also ErrResolver),
// or ctx ended. name is a DNS name without trailing dot; it need not be a
// normalized identifier (it may start with "_acme-challenge.").
type Resolver interface {
	// LookupA follows the CNAME chain from name and returns the terminal A
	// records (IPv4 only), in answer order, without duplicates.
	LookupA(ctx context.Context, name string) ([]netip.Addr, error)
	// LookupTXT returns the TXT strings at name. Each record is returned
	// as one string with its character-strings concatenated.
	LookupTXT(ctx context.Context, name string) ([]string, error)
	// LookupCAA returns the CAA RRset at exactly that node (after CNAME
	// resolution of the node itself). It does not climb the tree; the
	// caller implements RFC 8659 climbing.
	LookupCAA(ctx context.Context, name string) ([]CAA, error)
}

// ---------------------------------------------------------------------------
// Gate
// ---------------------------------------------------------------------------

// Gate makes the authorization decision for all three modes (architecture
// §3, §4.2, §16). Implemented by internal/gate.
type Gate interface {
	// Authorize decides whether the source address may obtain (acme,
	// direct) or present a challenge for (dnsproxy) the identifier set.
	// One decision covers the whole set.
	//
	// Order of evaluation:
	//  1. src must be IPv4 (not_ipv4); every name must be inside a managed
	//     zone (outside_managed_zone).
	//  2. Enabled grants matching src are looked up before any DNS query.
	//     With a wildcard=true grant everything is allowed (ip_grant).
	//     With an ordinary grant a set without wildcards is allowed
	//     (ip_grant); a set with wildcards is denied
	//     (wildcard_grant_required).
	//  3. Without a grant, wildcards are denied (wildcard_grant_required);
	//     otherwise every name must resolve (A, following CNAMEs) to src
	//     (dns_ip_match / dns_mismatch / dns_failure).
	//  4. Mode dnsproxy only, when allowed without a wildcard grant: each
	//     name must pass the CAA wildcard-protection check of architecture
	//     §3.2 (wildcard_unprotected).
	//
	// A denial is a Decision with Allowed=false and a nil error, including
	// when DNS resolution failed (reason dns_failure). The error is
	// non-nil only when the decision could not be made at all (grant store
	// failure, ctx done). The gate does not write audit records; the
	// caller does, with the full request context.
	Authorize(ctx context.Context, mode Mode, src netip.Addr, set names.Set) (Decision, error)
}

// CAAStatus describes whether public CAA protects the wildcard of a name.
type CAAStatus struct {
	Name string // the name that was checked
	// Node is the name where the effective CAA RRset was found; empty when
	// there is none anywhere up the tree.
	Node    string
	Records []CAA
	// WildcardProtected is the §3.2 verdict: no foreign ACME account can
	// obtain "*.Name".
	WildcardProtected bool
	// MissingProviders lists configured, enabled providers that the CAA
	// set does not allow to issue (which would break fallback).
	MissingProviders []string
	Detail           string // operator-readable explanation of the verdict
}

// CAAChecker reports CAA status for the UI. Implemented by internal/gate.
type CAAChecker interface {
	// CheckCAA evaluates the effective CAA RRset for a normalized name
	// (normally a managed zone apex). The error is non-nil when resolution
	// failed.
	CheckCAA(ctx context.Context, name string) (CAAStatus, error)
}

// ---------------------------------------------------------------------------
// Upstream CA
// ---------------------------------------------------------------------------

// ProviderCaps are the fixed properties of a provider that policy needs.
type ProviderCaps struct {
	// ARI: the CA serves renewal information and accepts `replaces`.
	ARI bool
	// ARIExempt: a `replaces` order inside the suggested window is exempt
	// from the CA's rate limits.
	ARIExempt bool
	// CAAIssuers are the CAA issuer domain names that authorize the CA.
	CAAIssuers []string
	// AccountURIHonoured: the CA enforces CAA `accounturi` (RFC 8657).
	AccountURIHonoured bool
}

// UpstreamStatus is the RFC 8555 status of an upstream order.
type UpstreamStatus string

const (
	UpstreamPending    UpstreamStatus = "pending"
	UpstreamReady      UpstreamStatus = "ready"
	UpstreamProcessing UpstreamStatus = "processing"
	UpstreamValid      UpstreamStatus = "valid"
	UpstreamInvalid    UpstreamStatus = "invalid"
)

// UpstreamOrder is the state of an order at the CA.
type UpstreamOrder struct {
	URL     string
	Status  UpstreamStatus
	Expires time.Time // zero if the CA did not say
	Names   []string  // identifiers as the CA reports them
	// Replaces is the ARI certificate identifier the order was created
	// with; empty for none.
	Replaces          string
	AuthorizationURLs []string
	FinalizeURL       string
	CertificateURL    string // set when Status is valid
	// Error is the CA's problem document when Status is invalid.
	Error *Problem
}

// UpstreamChallenge is the dns-01 challenge of one pending authorization.
type UpstreamChallenge struct {
	AuthorizationURL string
	URL              string // challenge URL
	// Identifier is the name being authorized, without wildcard label.
	Identifier string
	Wildcard   bool // the authorization is for "*."+Identifier
	// RecordName is where the value must be published:
	// names.ChallengeRecord(Identifier).
	RecordName string
	// Value is the TXT value to publish (base64url SHA-256 of the key
	// authorization).
	Value string
}

// RenewalInfo is ACME Renewal Information for one certificate (RFC 9773).
type RenewalInfo struct {
	WindowStart time.Time // suggestedWindow.start
	WindowEnd   time.Time // suggestedWindow.end
	// ExplanationURL is the optional explanationURL.
	ExplanationURL string
	// RetryAfter is how long to wait before asking again; 0 if the CA did
	// not say (callers then use their own default).
	RetryAfter time.Duration
}

// InWindow reports whether now is inside the suggested window
// (WindowStart <= now < WindowEnd) — the condition for an ARI-qualified
// renewal.
func (r RenewalInfo) InWindow(now time.Time) bool {
	return !now.Before(r.WindowStart) && now.Before(r.WindowEnd)
}

// Due reports whether renewal should be attempted: now is at or after the
// start of the window.
func (r RenewalInfo) Due(now time.Time) bool { return !now.Before(r.WindowStart) }

// Provider is one upstream CA account (architecture §9). Implemented by
// internal/upstream; faked by coretest.FakeCA.
//
// A Provider does exactly what it is asked: it holds no slots and no
// budgets, does not retry on rate-limit or outage answers, and does not
// decide policy. It may retry badNonce transparently. All calls for one
// provider use the same upstream account.
//
// Errors: every method returns either a context error (ctx done) or a
// *ProviderError whose Kind classifies the failure. Callers report every
// result (including nil) to Scheduler.ReportProvider.
type Provider interface {
	// Name is the configured provider name; constant.
	Name() string
	// Caps returns the provider's fixed capabilities; constant, no I/O.
	Caps() ProviderCaps
	// AccountURL returns the upstream account URL, registering the account
	// on first use (generating and persisting the account key, applying
	// EAB). Later calls return the stored URL without I/O.
	AccountURL(ctx context.Context) (string, error)
	// NewOrder creates an upstream order for the names (normalized,
	// wildcards allowed). replaces is an ARI certificate identifier or
	// empty. Each successful call creates a new order at the CA: never
	// call it twice for one broker order. If the CA refuses `replaces`
	// because a replacement order already exists the error Kind is
	// ProviderAlreadyReplaced and no order was created.
	//
	// When the call fails with ProviderDown or a context error the order
	// may or may not exist at the CA; the caller must assume it does.
	NewOrder(ctx context.Context, names []string, replaces string) (UpstreamOrder, error)
	// GetOrder fetches the current state of an order. An order unknown to
	// the CA (expired and purged) gives ProviderRejected.
	GetOrder(ctx context.Context, orderURL string) (UpstreamOrder, error)
	// DNSChallenges returns the dns-01 challenge of every authorization of
	// the order that is still pending. Authorizations already valid are
	// omitted, so an empty slice means there is nothing to prove. An
	// authorization that is invalid, or pending without a dns-01
	// challenge, gives ProviderRejected.
	DNSChallenges(ctx context.Context, order UpstreamOrder) ([]UpstreamChallenge, error)
	// Accept tells the CA the challenge is ready to be validated. Call it
	// only after the TXT value is publicly visible: some CAs validate
	// once and do not retry. Accepting a challenge that is already
	// processing or valid is a no-op.
	Accept(ctx context.Context, ch UpstreamChallenge) error
	// WaitReady polls the order until it leaves "pending" and returns it
	// with Status ready (or processing/valid if it is already further).
	// If the order becomes invalid the error is ProviderRejected carrying
	// the CA's problem. It gives up after UpstreamConfig.ValidationTimeout
	// with ProviderDown.
	WaitReady(ctx context.Context, orderURL string) (UpstreamOrder, error)
	// Finalize sends the CSR (DER) for a ready order and returns the order
	// as the CA answers (processing or valid). Sending the same CSR again
	// for an order that is already processing or valid is safe and returns
	// its current state without a second submission.
	//
	// When the call fails with ProviderDown or a context error the CSR may
	// have been accepted; the caller checks with GetOrder.
	Finalize(ctx context.Context, orderURL string, csrDER []byte) (UpstreamOrder, error)
	// WaitCertificate polls a finalized order until it is valid and
	// returns the certificate chain as PEM: leaf first, then
	// intermediates, no root. An order that becomes invalid gives
	// ProviderRejected. It gives up after UpstreamConfig.IssueTimeout with
	// ProviderDown; calling it again later continues waiting.
	WaitCertificate(ctx context.Context, orderURL string) (chainPEM []byte, err error)
	// RenewalInfo fetches renewal information for an ARI certificate
	// identifier. A provider without ARI (Caps().ARI false) and an
	// identifier the CA does not know both give ProviderRejected.
	RenewalInfo(ctx context.Context, ariCertID string) (RenewalInfo, error)
}

// Providers is the registry of configured upstream providers. Implemented by
// internal/upstream; it follows configuration reloads.
type Providers interface {
	// Get returns the provider with that name. Providers that are disabled
	// in the configuration are still returned (existing certificates may
	// need their renewal information); unknown names give false.
	Get(name string) (Provider, bool)
	// Enabled returns the enabled providers in order of preference; the
	// first is the primary.
	Enabled() []Provider
}

// ---------------------------------------------------------------------------
// DNS-01
// ---------------------------------------------------------------------------

// DNSEngine publishes and removes DNS-01 TXT values in Route53 (architecture
// §17). Implemented by internal/dns01; faked by coretest.FakeDNSEngine.
//
// The engine owns the Challenge rows: it creates them and moves them through
// their states. Concurrent values at one record name coexist in one RRset;
// the engine never removes a value that belongs to another active challenge.
type DNSEngine interface {
	// Present publishes value as a TXT record at record (a full record
	// name without trailing dot, normally names.ChallengeRecord(id)) and
	// returns once that exact value is visible through the public
	// Resolver. The challenge is then in state ready.
	//
	// It is idempotent per (owner, record, value): if a non-terminal
	// challenge with the same three exists, Present does not create
	// another one; it returns that challenge's ID once the value is
	// visible. This is how preparation is resumed after a restart.
	//
	// Errors: ErrOutsideManagedZones when record is in no managed zone
	// (nothing is created); ErrDNSPropagation when the value did not
	// become visible in time; other errors for Route53 failures; ctx
	// errors. On any error after the challenge was created the engine
	// removes the value again and the challenge ends as failed.
	Present(ctx context.Context, owner, record, value string) (challengeID string, err error)
	// Cleanup removes the challenge's own value from the RRset (deleting
	// the RRset when it was the last) and marks the challenge done. It is
	// idempotent: cleaning a challenge that is already done or failed
	// returns nil. An unknown ID gives ErrNotFound.
	Cleanup(ctx context.Context, challengeID string) error
	// CleanupOwner cleans up every non-terminal challenge of the owner.
	// No challenges is not an error. It returns the first error after
	// trying all of them.
	CleanupOwner(ctx context.Context, owner string) error
	// Reconcile is called once at startup and may be called again at any
	// time: for every record name with non-terminal challenges it makes
	// Route53 match the desired RRset (values of challenges whose state
	// WantsRecord), and it finishes challenges left in cleaning.
	// Challenges left in pending/presenting/waiting_dns by a crash stay
	// non-terminal with their value published; a later Present for the
	// same (owner, record, value) picks them up, and a later Cleanup or
	// CleanupOwner removes them.
	Reconcile(ctx context.Context) error
}

// ---------------------------------------------------------------------------
// Admission scheduler
// ---------------------------------------------------------------------------

// AdmissionRequest asks for permission to do upstream work for one order at
// one provider.
type AdmissionRequest struct {
	// Ref identifies the reservation; it is the Order.ID. One Ref has at
	// most one reservation: acquiring again for a Ref that already holds
	// one returns ErrConflict.
	Ref      string
	Provider string
	Names    names.Set
	Class    PriorityClass
	// Renewal says a certificate of this lineage exists (or the caller
	// otherwise knows this is a renewal); renewals may use the
	// renewal-reserved headroom of every budget.
	Renewal bool
	// ARIQualified says the order will carry `replaces`, the provider
	// exempts ARI renewals and now is inside the suggested window: no rate
	// budget is reserved, only a concurrency slot.
	ARIQualified bool
	// ReuseUpstreamOrder says an existing upstream order is being adopted:
	// no new-order budget is reserved.
	ReuseUpstreamOrder bool
	// MaxWait bounds the wait for a concurrency slot. 0 uses
	// SchedulerConfig.AdmitWait; a negative value does not wait at all.
	MaxWait time.Duration
}

// Scheduler is the central admission scheduler (architecture §10).
// Implemented by internal/sched. Nothing may call Provider.NewOrder or
// Provider.Finalize without holding a Ticket for that provider.
type Scheduler interface {
	// Acquire admits the request or refuses it.
	//
	// Checks, in order:
	//  1. provider circuit: if admission is closed the request is refused
	//     at once with AdmissionProviderDown or AdmissionRateLimited and a
	//     RetryAfter reaching to the circuit's reopening;
	//  2. rate budgets (skipped when ARIQualified; new-order budget
	//     skipped when ReuseUpstreamOrder): if any budget has no room for
	//     this request it is refused at once with AdmissionRateLimited and
	//     a RetryAfter reaching to when the oldest counted event leaves
	//     the window; otherwise one unit of each is reserved (durably);
	//  3. concurrency slot: the request waits, by Class then arrival, for
	//     up to MaxWait; on timeout the reservation is returned and the
	//     request is refused with AdmissionBusy.
	//
	// On success the caller holds a slot and the reservation until it
	// calls the Ticket's methods. If ctx ends while waiting, nothing is
	// held and ctx.Err() is returned.
	Acquire(ctx context.Context, req AdmissionRequest) (Ticket, error)
	// Reattach returns a Ticket for a reservation that survived a restart
	// (or whose Ticket was dropped), identified by Ref. The ticket holds
	// no concurrency slot. ErrNotFound when the Ref has no open
	// reservation — which is also the case for requests admitted as
	// ARIQualified with nothing reserved; callers treat that as "nothing
	// to settle".
	Reattach(ctx context.Context, ref string) (Ticket, error)
	// OpenRefs lists the Refs that still hold a reservation, for startup
	// reconciliation: a Ref that belongs to no live order is settled by
	// the recovery code.
	OpenRefs(ctx context.Context) ([]string, error)
	// ReportProvider feeds the provider circuit with the outcome of an
	// upstream call. err is the error returned by a Provider method, or
	// nil for success. *ProviderError kinds rate_limited, busy and down
	// close admission until now+RetryAfter (or the configured default,
	// growing with consecutive failures for "down"); the state is
	// persisted. nil resets the failure count and reopens a circuit whose
	// RetryAfter has passed. Other errors (rejected, already_replaced,
	// context errors) are ignored.
	ReportProvider(ctx context.Context, provider string, err error)
	// Snapshot returns the current state for the UI and metrics. No I/O.
	Snapshot() SchedulerSnapshot
}

// Ticket is an admitted request: a concurrency slot plus a budget
// reservation. All methods are idempotent, safe for concurrent use and never
// block on anything but local persistence.
//
// Settlement rules:
//
//	                 new-order budget              certificate budgets
//	OrderCreated     consumed (permanently)        still reserved
//	Commit           consumed if OrderCreated      consumed
//	                 was called, else returned
//	Refund           consumed if OrderCreated      returned
//	                 was called, else returned
//
// The first of Commit and Refund wins; later calls do nothing.
type Ticket interface {
	// Ref returns the AdmissionRequest.Ref.
	Ref() string
	// OrderCreated records that an upstream newOrder call is about to be
	// made. Call it before Provider.NewOrder, in the same step that
	// persists the order's intent, so that a crash can never leave an
	// upstream order that was not counted.
	OrderCreated()
	// PrepDone releases the concurrency slot (preparation finished or was
	// abandoned). The reservation stays.
	PrepDone()
	// Commit settles the reservation after a certificate was issued. It
	// also releases the slot if still held.
	Commit()
	// Refund settles the reservation when no certificate was or will be
	// issued (order expired, failed before or at finalize). It also
	// releases the slot if still held.
	Refund()
}

// BudgetUsage is the usage of one budget bucket.
type BudgetUsage struct {
	Kind BudgetKind
	Key  string // see BudgetKind
	// Used counts reserved and committed events inside the window.
	Used int
	// Limit is the configured Count; RenewalOnly is the part of it only
	// renewals may use.
	Limit       int
	RenewalOnly int
	Window      time.Duration
}

// ProviderSnapshot is the scheduler's view of one provider.
type ProviderSnapshot struct {
	Name  string
	State ProviderState
	// Open is State.OpenAt(now) at snapshot time.
	Open       bool
	SlotsInUse int
	SlotsTotal int
	Waiting    int // requests waiting for a slot
	Reserved   int // open reservations (distinct Refs)
	// Budgets holds the new-order bucket and every per-domain and per-set
	// bucket with non-zero usage.
	Budgets []BudgetUsage
}

// SchedulerSnapshot is a point-in-time view of the scheduler.
type SchedulerSnapshot struct {
	At        time.Time
	Providers []ProviderSnapshot // in configuration order
}

// ---------------------------------------------------------------------------
// Issuance engine
// ---------------------------------------------------------------------------

// AdmitRequest is a gate-approved downstream newOrder.
type AdmitRequest struct {
	AccountID string    // downstream ACME account
	Names     names.Set // normalized, inside managed zones
	// Replaces is the `replaces` field of the downstream newOrder, verbatim
	// (an ARI certificate identifier), or empty.
	Replaces string
	SourceIP netip.Addr
	// Decision is the gate's allow decision for this request; it is
	// recorded with the order and in the audit log.
	Decision Decision
}

// FinalizeRequest is a gate-approved downstream finalize.
type FinalizeRequest struct {
	OrderID   string
	AccountID string // must own the order, otherwise ErrNotFound
	CSRDER    []byte
	SourceIP  netip.Addr
}

// IssueRequest is a gate-approved direct-mode issuance.
type IssueRequest struct {
	// Identifier is the single normalized name ("foo.example.com" or
	// "*.example.com").
	Identifier string
	// CSRDER is the CSR for exactly that identifier, signed by the cache
	// object's key.
	CSRDER   []byte
	SourceIP netip.Addr // requester that triggered it; zero for none
	Decision Decision
	// Background marks a renewal started behind a served response: it
	// gets the lowest priority unless the engine finds the certificate
	// inside its emergency window.
	Background bool
}

// Issuer is the issuance engine (architecture §7, §8, §20). Implemented by
// internal/issuance. Front ends call the Gate first and pass the decision;
// the engine does not authorize, it orchestrates: provider choice, admission,
// upstream order, DNS-01, finalize, persistence, audit of issuance results.
//
// Error vocabulary of all methods: *AdmissionError (refused locally; nothing
// happened upstream), *Problem (the request is wrong; show it to the client),
// *ProviderError (upstream failed), ErrNotFound, ErrExpired, ErrCSRMismatch,
// context errors. ProblemFromError turns any of them into an ACME problem.
type Issuer interface {
	// Admit handles a downstream newOrder (architecture §7.1 steps 4–7).
	//
	// If the account already has an unexpired order in status ready for
	// the same identifier set, that order is returned and nothing else
	// happens. Otherwise the engine chooses a provider, waits for
	// admission (up to SchedulerConfig.AdmitWait), persists a new Order
	// (Status ready, Prep intent — or Prep prepared when it adopts an
	// abandoned upstream order) and starts upstream preparation in the
	// background. The background work is not tied to ctx.
	//
	// Refusal by every eligible provider returns an *AdmissionError:
	// provider_down only if all were down, otherwise rate_limited/busy
	// with the smallest RetryAfter. No order is persisted and nothing was
	// created upstream.
	Admit(ctx context.Context, req AdmitRequest) (*Order, error)
	// Finalize handles a downstream finalize (architecture §7.2 steps
	// 2–9).
	//
	// It validates the CSR (parses, signature, no extra names, names
	// equal to the order's set; violations are *Problem badCSR), records
	// it (idempotency by CSR hash: the same CSR again reuses the existing
	// state, a different CSR gives ErrCSRMismatch and never reaches
	// upstream), then waits up to SchedulerConfig.FinalizeWait for the
	// order to become valid or invalid and returns the order as it is at
	// that moment: Status processing means "poll the order". An order
	// that ended invalid is returned with a nil error and Order.Error set.
	//
	// ErrNotFound: no such order for that account. ErrExpired: the order
	// expired before any CSR was recorded. Once the CSR is recorded,
	// issuance continues to completion independently of ctx.
	Finalize(ctx context.Context, req FinalizeRequest) (*Order, error)
	// Issue performs a whole direct-mode issuance synchronously:
	// admission, upstream order (or adoption), DNS-01, finalize with the
	// given CSR, persistence. It returns the certificate with ChainPEM
	// set (the store does not keep direct-mode chains; the caller writes
	// the generation to disk). The caller guarantees at most one
	// concurrent Issue per identifier.
	//
	// If ctx ends before the CSR was sent upstream the attempt is
	// abandoned and refunded. After that point the engine finishes the
	// issuance in the background and Issue returns the context error; the
	// certificate is not delivered (direct mode then issues again later).
	Issue(ctx context.Context, req IssueRequest) (*Certificate, error)
	// RenewalInfo returns renewal information for a certificate the
	// broker issued, fetched from the provider that issued it (cached
	// until the provider's RetryAfter). It also records a lineage
	// observation for the certificate's identifier set. ErrNotFound when
	// the broker did not issue such a certificate or its provider is no
	// longer configured.
	RenewalInfo(ctx context.Context, ariCertID string) (RenewalInfo, error)
	// Recover is called once at startup, before any front end serves
	// requests. It applies architecture §20 to every non-terminal order:
	// intent without upstream URL becomes invalid with the new-order
	// budget counted as spent; orders with an upstream URL are resumed
	// (ACME mode) or failed and refunded (direct mode: the caller's key
	// context is gone; the upstream order stays adoptable if it was
	// prepared). Reservations that belong to no live order are settled.
	// Resumed work continues in the background after Recover returns.
	Recover(ctx context.Context) error
	// Sweep does periodic housekeeping; the app calls it about once a
	// minute. It expires orders that were never finalized (refunding
	// their reservations and cleaning their DNS challenges) and compacts
	// old protocol state.
	Sweep(ctx context.Context) error
}

// ---------------------------------------------------------------------------
// Audit
// ---------------------------------------------------------------------------

// Auditor appends events to the audit log. Implemented by internal/audit;
// faked by coretest.FakeAuditor.
type Auditor interface {
	// Record appends the event. It fills in Time when zero. It never
	// fails from the caller's point of view: write errors are logged and
	// counted by the implementation, not returned, because an audit
	// failure must not change the outcome of the audited operation.
	Record(ctx context.Context, ev AuditEvent)
}

// AuditQuery selects audit events for the UI.
type AuditQuery struct {
	// IncludeAdmin includes admin-only events; false returns public ones.
	IncludeAdmin bool
	// Since / Until bound Time (inclusive / exclusive); zero is unbounded.
	Since, Until time.Time
	// Type, Mode filter exactly when non-empty.
	Type string
	Mode Mode
	// Contains is a case-insensitive substring matched against source IP,
	// names, username, provider, reason and detail; empty matches all.
	Contains string
	// Limit caps the result; 0 means 200.
	Limit int
}

// AuditReader reads the audit log for the UI. Implemented by internal/audit.
type AuditReader interface {
	// Query returns matching events, newest first.
	Query(ctx context.Context, q AuditQuery) ([]AuditEvent, error)
}

// ---------------------------------------------------------------------------
// Human authentication
// ---------------------------------------------------------------------------

// Directory verifies human credentials against LDAP (architecture §5).
// Implemented by internal/auth; faked by coretest.FakeDirectory.
type Directory interface {
	// Authenticate searches for the user with the configured base and
	// filter (escaping the username) and verifies the password by
	// binding. nil means the credentials are good. ErrInvalidCredentials
	// covers: no such user, user not matching the filter, more than one
	// match, wrong password, empty password. Every other failure (LDAP
	// not configured, unreachable, bind account rejected, bad filter)
	// matches ErrDirectoryUnavailable.
	Authenticate(ctx context.Context, username, password string) error
}

// LDAPTester tests candidate LDAP settings before a configuration generation
// is activated. Implemented by internal/auth, used by internal/config.
type LDAPTester interface {
	// TestLDAP connects, binds with the service account (password taken
	// from the SecretStore by the implementation) and runs the user filter
	// for a probe name to prove the base and filter are usable. nil means
	// the settings work.
	TestLDAP(ctx context.Context, cfg LDAPConfig) error
}

// Login is the result of a successful login.
type Login struct {
	// Token is the opaque session token for the cookie. It is returned
	// only here; the store keeps its hash.
	Token   string
	Session Session
	User    User
}

// Authenticator is login and session handling for the UI. Implemented by
// internal/auth.
type Authenticator interface {
	// Login verifies the credentials (local break-glass admin first, then
	// the Directory), creates the user row on first login, applies
	// bootstrap admin roles and creates a session.
	//
	// Errors: ErrInvalidCredentials; ErrDirectoryUnavailable (LDAP down
	// or not configured and the user is not the local admin). Being
	// blocked is not a login error: a blocked user may log in and see the
	// views allowed to blocked users; callers check User.Blocked.
	Login(ctx context.Context, username, password string, src netip.Addr) (*Login, error)
	// Session resolves a cookie token to its session and user. The user
	// is read fresh, so role and blocked changes apply immediately.
	// ErrNotFound for an unknown token, ErrExpired for an expired session
	// (which is deleted).
	Session(ctx context.Context, token string) (*Session, *User, error)
	// Logout deletes the session; an unknown token is not an error.
	Logout(ctx context.Context, token string) error
}
