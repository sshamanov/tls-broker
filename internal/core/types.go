package core

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"net/netip"
	"time"

	"tls-broker/internal/names"
)

// NewID returns a new random identifier: 128 bits, 22 URL-safe characters.
// It is used for orders, certificates, ACME accounts and challenges.
func NewID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic("core: crypto/rand failed: " + err.Error())
	}
	return base64.RawURLEncoding.EncodeToString(b[:])
}

// NewToken returns a new random secret token: 256 bits, URL-safe. It is used
// for session cookies and CSRF tokens.
func NewToken() string {
	var b [32]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic("core: crypto/rand failed: " + err.Error())
	}
	return base64.RawURLEncoding.EncodeToString(b[:])
}

// HashToken returns the lowercase hex SHA-256 of a token. Sessions are stored
// and looked up by this hash, never by the token itself.
func HashToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

// CSRHash returns the lowercase hex SHA-256 of a DER-encoded CSR. It is the
// idempotency key of finalize.
func CSRHash(csrDER []byte) string {
	sum := sha256.Sum256(csrDER)
	return hex.EncodeToString(sum[:])
}

// ARICertID returns the ACME Renewal Information certificate identifier of a
// certificate (RFC 9773 §4.1): base64url(authority key identifier) "."
// base64url(DER serial number). It fails when the certificate has no
// authority key identifier.
func ARICertID(cert *x509.Certificate) (string, error) {
	if len(cert.AuthorityKeyId) == 0 {
		return "", errors.New("certificate has no authority key identifier")
	}
	der, err := asn1.Marshal(cert.SerialNumber)
	if err != nil {
		return "", err
	}
	var raw asn1.RawValue
	if _, err := asn1.Unmarshal(der, &raw); err != nil {
		return "", err
	}
	enc := base64.RawURLEncoding
	return enc.EncodeToString(cert.AuthorityKeyId) + "." + enc.EncodeToString(raw.Bytes), nil
}

// Mode is the front end a request came through.
type Mode string

const (
	ModeACME     Mode = "acme"     // clean ACME proxy
	ModeDirect   Mode = "direct"   // direct certificate API
	ModeDNSProxy Mode = "dnsproxy" // DNS proxy
	ModeUI       Mode = "ui"       // human control plane (audit only)
)

// ---------------------------------------------------------------------------
// Users, grants, sessions
// ---------------------------------------------------------------------------

// Role is a user's local role (architecture §4.1). Roles are ordered:
// admin > wildcard_allowed > normal.
type Role string

const (
	RoleNormal          Role = "normal"
	RoleWildcardAllowed Role = "wildcard_allowed"
	RoleAdmin           Role = "admin"
)

func (r Role) rank() int {
	switch r {
	case RoleNormal:
		return 1
	case RoleWildcardAllowed:
		return 2
	case RoleAdmin:
		return 3
	}
	return 0
}

// Valid reports whether r is one of the three roles.
func (r Role) Valid() bool { return r.rank() > 0 }

// AtLeast reports whether r is the same as or higher than min. An invalid
// role is not at least anything.
func (r Role) AtLeast(min Role) bool { return r.rank() > 0 && r.rank() >= min.rank() }

// User is a human known to the control plane. A user row is created at first
// successful login. (Username, Local) is unique: the local break-glass admin
// and an LDAP user of the same name are different users.
type User struct {
	ID       int64
	Username string // as normalized by auth: trimmed, lower case
	Role     Role
	// Blocked removes every issuance and control right regardless of Role
	// and takes effect immediately, also for existing sessions.
	Blocked bool
	// Local marks the break-glass admin, which authenticates without LDAP.
	Local       bool
	CreatedAt   time.Time
	LastLoginAt time.Time // zero until the first login is recorded
}

// EffectiveRole is the role the user can exercise now: "" when blocked,
// otherwise Role.
func (u *User) EffectiveRole() Role {
	if u == nil || u.Blocked {
		return ""
	}
	return u.Role
}

// Can reports whether the user is not blocked and has at least the role.
func (u *User) Can(min Role) bool { return u.EffectiveRole().AtLeast(min) }

// Grant is an IP grant: a durable capability attached to a source address or
// CIDR (architecture §4.2). Its effect depends only on its own fields, never
// on the current state of its owner. Grants are not scoped by name.
type Grant struct {
	ID          int64
	OwnerUserID int64        // who created it; informational for the gate
	Prefix      netip.Prefix // IPv4 only; a single address is a /32, always masked
	Enabled     bool
	Wildcard    bool // permits wildcard identifiers
	Note        string
	CreatedAt   time.Time
}

// Session is a logged-in browser session. The cookie carries an opaque token
// (NewToken); the store only ever sees HashToken(token).
type Session struct {
	TokenHash string // primary key: HashToken(cookie token)
	UserID    int64
	CSRFToken string // per-session token required on state-changing requests
	SourceIP  netip.Addr
	CreatedAt time.Time
	ExpiresAt time.Time // the session is invalid at and after this time
	// LastSeenAt is updated at most once per minute by the auth layer.
	LastSeenAt time.Time
}

// ---------------------------------------------------------------------------
// Downstream ACME accounts
// ---------------------------------------------------------------------------

// AccountStatus is the RFC 8555 account status.
type AccountStatus string

const (
	AccountValid       AccountStatus = "valid"
	AccountDeactivated AccountStatus = "deactivated"
)

// ACMEAccount is a downstream ACME account: protocol state only, never an
// identity or a permission (architecture §6).
type ACMEAccount struct {
	ID string
	// Thumbprint is the RFC 7638 SHA-256 JWK thumbprint, base64url without
	// padding. Unique among accounts.
	Thumbprint string
	JWK        []byte // public key as a JSON Web Key
	Status     AccountStatus
	Contact    []string // "mailto:..." URLs; metadata only
	CreatedAt  time.Time
}

// ---------------------------------------------------------------------------
// Orders
// ---------------------------------------------------------------------------

// OrderStatus is the status of a broker order as an ACME client sees it.
// "pending" does not exist: authorizations are valid from the start.
type OrderStatus string

const (
	// OrderReady: admitted, no CSR received yet.
	OrderReady OrderStatus = "ready"
	// OrderProcessing: a CSR was accepted and recorded; issuance runs to
	// completion with or without the client.
	OrderProcessing OrderStatus = "processing"
	// OrderValid: certificate issued and stored (CertificateID set).
	OrderValid OrderStatus = "valid"
	// OrderInvalid: failed, expired or abandoned (Error set). Terminal.
	OrderInvalid OrderStatus = "invalid"
)

// Terminal reports whether the status can never change again.
func (s OrderStatus) Terminal() bool { return s == OrderValid || s == OrderInvalid }

// PrepState tracks the upstream preparation of an order (upstream order
// created, DNS-01 done, CA validated), independently of OrderStatus.
type PrepState string

const (
	// PrepIntent: the decision to create an upstream order is recorded;
	// the upstream call may or may not have happened; no URL is known.
	PrepIntent PrepState = "intent"
	// PrepPreparing: the upstream order exists (UpstreamOrderURL set) and
	// its authorizations are being validated.
	PrepPreparing PrepState = "preparing"
	// PrepPrepared: the upstream order is ready for finalize.
	PrepPrepared PrepState = "prepared"
	// PrepFailed: preparation failed; the order is invalid.
	PrepFailed PrepState = "failed"
)

// PriorityClass orders waiting admission requests; a lower number is served
// first (architecture §10).
type PriorityClass int

const (
	ClassARIRenewal       PriorityClass = 1 // ARI-qualified renewals
	ClassDirectEmergency  PriorityClass = 2 // direct cache inside the emergency window
	ClassACMEEmergency    PriorityClass = 3 // ACME renewals inside the emergency window
	ClassACMEOrdinary     PriorityClass = 4 // ordinary ACME issuance and renewal
	ClassDirectMiss       PriorityClass = 5 // direct cache misses
	ClassDirectBackground PriorityClass = 6 // direct cache background renewal
)

// Valid reports whether c is one of the six classes.
func (c PriorityClass) Valid() bool { return c >= ClassARIRenewal && c <= ClassDirectBackground }

func (c PriorityClass) String() string {
	switch c {
	case ClassARIRenewal:
		return "ari_renewal"
	case ClassDirectEmergency:
		return "direct_emergency"
	case ClassACMEEmergency:
		return "acme_emergency"
	case ClassACMEOrdinary:
		return "acme_ordinary"
	case ClassDirectMiss:
		return "direct_miss"
	case ClassDirectBackground:
		return "direct_background"
	}
	return "unknown"
}

// Order is one issuance attempt handled by the broker: a downstream ACME
// order (Mode acme) or one direct-mode issuance job (Mode direct). It maps to
// at most one upstream order, ever.
//
// Lifecycle (who changes what is documented on OrderStore):
//
//	Create          Status=ready       Prep=intent
//	SetUpstream                        Prep=preparing  UpstreamOrderURL set
//	SetPrepared                        Prep=prepared
//	BeginFinalize   Status=processing                  CSRHash, CSRDER set
//	Complete        Status=valid                       CertificateID set, CSRDER cleared
//	Fail/ExpireDue  Status=invalid                     Error set
//
// BeginFinalize may happen while Prep is still intent or preparing; the
// engine then finalizes upstream as soon as preparation ends.
type Order struct {
	ID   string
	Mode Mode // ModeACME or ModeDirect
	// AccountID is the downstream ACME account; empty for direct mode.
	AccountID string
	Names     names.Set
	// Replaces is the ARI certificate identifier the downstream client
	// sent in newOrder, verbatim; empty when it sent none.
	Replaces string
	SourceIP netip.Addr // source of the request that created the order
	GrantID  int64      // grant that authorized it; 0 when authorized by DNS

	Status OrderStatus
	Prep   PrepState
	Class  PriorityClass
	// ARIQualified records that the order was admitted as an ARI-qualified
	// renewal (provider exempts ARI and admission was inside the window).
	ARIQualified bool

	// Provider is the upstream provider chosen at admission; it never
	// changes for the life of the order.
	Provider string
	// UpstreamOrderURL is empty until the upstream order is known.
	UpstreamOrderURL string
	// UpstreamReplaces is the ARI certificate identifier actually sent
	// upstream (supplied by the client or inferred); empty for none.
	UpstreamReplaces string
	// UpstreamExpiresAt is when the upstream order expires; zero if unknown.
	UpstreamExpiresAt time.Time
	// AdoptedByOrderID is set on an expired order whose upstream order was
	// taken over by a later order. Such an order no longer owns its
	// UpstreamOrderURL.
	AdoptedByOrderID string

	// CSRHash is CSRHash(csr) of the accepted CSR; empty until finalize.
	CSRHash string
	// CSRDER is kept from finalize until the order is terminal, so that a
	// restart can resume; nil otherwise.
	CSRDER []byte
	// CertificateID is set when Status is valid.
	CertificateID string
	// Error is set when Status is invalid.
	Error *Problem

	CreatedAt time.Time
	// ExpiresAt bounds the wait for finalize: an order still in Status
	// ready at or after this time is expired by ExpireDue. It has no
	// effect once a CSR is recorded.
	ExpiresAt time.Time
	UpdatedAt time.Time // set by the store to the `now` of the last change
}

// Finalized reports whether a CSR has been recorded for the order.
func (o *Order) Finalized() bool { return o.CSRHash != "" }

// ---------------------------------------------------------------------------
// Certificates and lineages
// ---------------------------------------------------------------------------

// Certificate is a certificate the broker obtained from an upstream CA, with
// the mapping needed for ARI and renewal continuity (architecture §8).
type Certificate struct {
	ID      string
	OrderID string // the Order that produced it
	Mode    Mode   // ModeACME or ModeDirect
	Names   names.Set

	Provider   string // upstream provider name
	AccountURL string // upstream account that issued it
	Serial     string // lowercase hex, no separators, no leading zeros
	// ARICertID is ARICertID(leaf); unique among certificates. Empty only
	// if the leaf has no authority key identifier.
	ARICertID string
	NotBefore time.Time
	NotAfter  time.Time
	IssuedAt  time.Time // when the broker stored it

	// SourceIP and GrantID record who obtained the certificate: the
	// requesting address of the order that produced it and the grant that
	// authorized that order (0 when the names resolved to the requester).
	// OrderStore.Complete copies both from the order. Both are zero for
	// certificates stored before schema version 2 whose order was pruned.
	SourceIP netip.Addr
	GrantID  int64

	// ChainPEM is the leaf followed by intermediates, without the root, as
	// returned by the CA. It is stored for ACME-mode certificates. For
	// direct-mode certificates the store saves no chain (the files on disk
	// are the truth) and returns nil here.
	ChainPEM []byte

	// ReplacesID is the certificate this one replaced (the predecessor
	// named in the upstream `replaces`), empty for none.
	ReplacesID string
	// ReplacedByID is the certificate that replaced this one, empty while
	// it is the newest of its line.
	ReplacedByID string
}

// Lifetime is NotAfter - NotBefore.
func (c *Certificate) Lifetime() time.Duration { return c.NotAfter.Sub(c.NotBefore) }

// MinLineageGap is the smallest gap between two requests of a lineage that
// counts as a new "check". Requests closer together are one visit (an ARI
// poll followed by the order it triggers).
const MinLineageGap = time.Hour

// Lineage tracks how often the clients of one certificate lineage come back.
// A lineage is identified by the normalized identifier set (names.Set.Key).
type Lineage struct {
	Key string // names.Set.Key()
	// LastRequestAt is the time of the last request that counted (the
	// anchor for the next gap). Zero when nothing has been seen.
	LastRequestAt time.Time
	// ObservedInterval is the smoothed gap between counted requests; valid
	// only when Samples > 0.
	ObservedInterval time.Duration
	// Samples is the number of gaps observed so far.
	Samples int
}

// Observe returns the lineage after a request at time `at`. It is the one
// definition of lineage tracking; LineageStore.Observe applies it atomically.
//
//   - first request ever: becomes the anchor, no sample;
//   - gap since the anchor below MinLineageGap (or negative): ignored, the
//     anchor stays;
//   - otherwise the gap is a sample: the first sample sets ObservedInterval,
//     later ones move it by a quarter of the difference
//     (interval = (3*interval + gap) / 4); the request becomes the anchor.
func (l Lineage) Observe(at time.Time) Lineage {
	if l.LastRequestAt.IsZero() {
		l.LastRequestAt = at
		return l
	}
	gap := at.Sub(l.LastRequestAt)
	if gap < MinLineageGap {
		return l
	}
	if l.Samples == 0 {
		l.ObservedInterval = gap
	} else {
		l.ObservedInterval = (3*l.ObservedInterval + gap) / 4
	}
	l.Samples++
	l.LastRequestAt = at
	return l
}

// Interval returns the observed check interval, or def until at least one
// gap has been observed (two requests seen).
func (l Lineage) Interval(def time.Duration) time.Duration {
	if l.Samples == 0 || l.ObservedInterval <= 0 {
		return def
	}
	return l.ObservedInterval
}

// EmergencyWindow is the formula of architecture §8:
//
//	fraction*lifetime + safetyChecks*checkInterval, capped at lifetime/2.
//
// A renewal is an emergency when now is at or after NotAfter minus this.
func EmergencyWindow(cfg EmergencyConfig, lifetime, checkInterval time.Duration) time.Duration {
	w := time.Duration(cfg.Fraction*float64(lifetime)) + time.Duration(cfg.SafetyChecks)*checkInterval
	if max := lifetime / 2; w > max {
		w = max
	}
	if w < 0 {
		w = 0
	}
	return w
}

// ---------------------------------------------------------------------------
// DNS-01 challenges
// ---------------------------------------------------------------------------

// ChallengeState is the state of one TXT value in the DNS-01 engine
// (architecture §17).
type ChallengeState string

const (
	ChallengePending    ChallengeState = "pending"     // recorded, not yet written
	ChallengePresenting ChallengeState = "presenting"  // Route53 change submitted
	ChallengeWaitingDNS ChallengeState = "waiting_dns" // written, waiting for public visibility
	ChallengeReady      ChallengeState = "ready"       // visible in public DNS
	ChallengeCleaning   ChallengeState = "cleaning"    // removal in progress
	ChallengeDone       ChallengeState = "done"        // removed; terminal
	ChallengeFailed     ChallengeState = "failed"      // gave up, value removed or never written; terminal
)

// Terminal reports whether the challenge is finished (done or failed).
func (s ChallengeState) Terminal() bool { return s == ChallengeDone || s == ChallengeFailed }

// WantsRecord reports whether a challenge in this state wants its value to be
// part of the TXT RRset (pending, presenting, waiting_dns, ready). The
// desired RRset of a record name is exactly the values of its challenges for
// which this is true.
func (s ChallengeState) WantsRecord() bool {
	switch s {
	case ChallengePending, ChallengePresenting, ChallengeWaitingDNS, ChallengeReady:
		return true
	}
	return false
}

// Challenge is one TXT value at one _acme-challenge record.
type Challenge struct {
	ID     string
	ZoneID string // Route53 hosted zone ID
	// RecordName is the full record name without trailing dot, for example
	// "_acme-challenge.foo.example.com".
	RecordName string
	Value      string // TXT value, unquoted
	// Owner says who asked for the value; see OrderOwner and DNSProxyOwner.
	Owner     string
	State     ChallengeState
	Error     string // last failure, for operators
	CreatedAt time.Time
	UpdatedAt time.Time
}

// OrderOwner is the Challenge.Owner of values presented for a broker order.
func OrderOwner(orderID string) string { return "order:" + orderID }

// DNSProxyOwner is the Challenge.Owner of values presented through the DNS
// proxy by the given source address. Cleanup is accepted only from an address
// that maps to the same owner or holds a grant.
func DNSProxyOwner(src netip.Addr) string { return "dnsproxy:" + src.String() }

// ---------------------------------------------------------------------------
// Direct cache
// ---------------------------------------------------------------------------

// DirectEntry is the metadata of one direct-mode cache object (architecture
// §11–12). Key and certificate files live on disk under
// <data>/certs/<dir>/generations/<n>/; this row points at the active one.
type DirectEntry struct {
	// Identifier is the normalized name ("foo.example.com" or
	// "*.example.com"); primary key.
	Identifier string
	// Generation is the active generation number, 0 when there is none yet.
	Generation    int
	CertificateID string // Certificate of the active generation; empty if none
	Provider      string
	NotBefore     time.Time
	NotAfter      time.Time
	// RenewAt is when renewal becomes due (from ARI, or a fraction of the
	// lifetime). Zero means "not scheduled".
	RenewAt time.Time
	// NextARICheckAt is when renewal information should be fetched again.
	NextARICheckAt time.Time
	// LastFetchAt / LastFetchIP describe the most recent client fetch.
	LastFetchAt time.Time
	LastFetchIP netip.Addr
	// LastAttemptAt, LastError and Failures describe the most recent
	// issuance or renewal attempt; Failures counts consecutive failures and
	// is 0 after a success.
	LastAttemptAt time.Time
	LastError     string
	Failures      int
	CreatedAt     time.Time
	UpdatedAt     time.Time
}

// ---------------------------------------------------------------------------
// Provider state and budgets
// ---------------------------------------------------------------------------

// ProviderHealth is the admission state of a provider.
type ProviderHealth string

const (
	// ProviderHealthy: admission is open.
	ProviderHealthy ProviderHealth = "healthy"
	// ProviderLimited: the provider signalled a rate limit or asked to
	// back off; admission is closed until RetryAfter.
	ProviderLimited ProviderHealth = "rate_limited"
	// ProviderUnavailable: the provider is down; admission is closed until
	// RetryAfter, when one probe request is let through.
	ProviderUnavailable ProviderHealth = "down"
)

// ProviderState is the persisted circuit state of one provider.
type ProviderState struct {
	Name   string
	Health ProviderHealth
	// RetryAfter is the absolute time until which admission is closed.
	// At or after it the provider is treated as healthy again whatever
	// Health says.
	RetryAfter time.Time
	LastError  string // text of the error that last changed the state
	// Failures counts consecutive health-affecting failures.
	Failures  int
	UpdatedAt time.Time
}

// OpenAt reports whether admission to the provider is open at time now.
func (s ProviderState) OpenAt(now time.Time) bool {
	return s.Health == ProviderHealthy || s.Health == "" || !now.Before(s.RetryAfter)
}

// BudgetKind names a sliding-window rate budget.
type BudgetKind string

const (
	// BudgetNewOrder: upstream newOrder calls per account. Key is "".
	BudgetNewOrder BudgetKind = "new_order"
	// BudgetCertDomain: certificates per registered domain. Key is the
	// registered domain (names.RegisteredDomain).
	BudgetCertDomain BudgetKind = "cert_domain"
	// BudgetCertSet: certificates per exact identifier set. Key is
	// names.Set.Key().
	BudgetCertSet BudgetKind = "cert_set"
)

// BudgetState is the state of a budget event.
type BudgetState string

const (
	// BudgetReserved: held by an admitted request that has not finished.
	BudgetReserved BudgetState = "reserved"
	// BudgetCommitted: consumed; counts until it leaves the window.
	BudgetCommitted BudgetState = "committed"
)

// BudgetEvent is one unit of one budget, reserved or consumed at time At.
// Both states count against the budget while At is inside the window.
type BudgetEvent struct {
	ID       int64  // assigned by the store
	Ref      string // AdmissionRequest.Ref of the request that owns it
	Provider string
	Kind     BudgetKind
	Key      string
	At       time.Time
	State    BudgetState
	// Renewal records that the event was admitted as a renewal (it may sit
	// in the renewal-reserved headroom).
	Renewal bool
}

// ---------------------------------------------------------------------------
// Gate decisions and audit
// ---------------------------------------------------------------------------

// Decision reasons (architecture §14). They appear in audit records and in
// responses; treat them as a stable vocabulary.
const (
	ReasonDNSIPMatch            = "dns_ip_match"            // allow: every name resolves to the source
	ReasonIPGrant               = "ip_grant"                // allow: explicit grant
	ReasonWildcardGrantRequired = "wildcard_grant_required" // deny: wildcard without wildcard grant
	ReasonWildcardUnprotected   = "wildcard_unprotected"    // deny: DNS proxy, CAA does not close *.N
	ReasonDNSMismatch           = "dns_mismatch"            // deny: a name does not resolve to the source
	ReasonDNSFailure            = "dns_failure"             // deny: resolvers failed; retryable
	ReasonOutsideManagedZone    = "outside_managed_zone"    // deny
	ReasonInvalidIdentifier     = "invalid_identifier"      // deny
	ReasonNotIPv4               = "not_ipv4"                // deny: source is not an IPv4 address
	ReasonBlocked               = "blocked"                 // deny: blocked user (control plane)
	ReasonRateLimited           = "rate_limited"            // refused by the scheduler
	ReasonProviderUnavailable   = "provider_unavailable"    // no provider could take it
)

// Decision is the gate's answer for one request (one identifier set).
type Decision struct {
	Allowed bool
	Reason  string // one of the Reason constants
	// GrantID is the grant that allowed the request; 0 when it was allowed
	// by DNS or denied.
	GrantID int64
	// Name is the identifier that caused a denial, when one can be named.
	Name string
	// Detail is operator-readable context (resolved addresses, CAA value).
	Detail string
}

// Audit event types (AuditEvent.Type).
const (
	AuditGate          = "gate"              // an authorization decision
	AuditOrder         = "order"             // order admitted or refused
	AuditIssue         = "issue"             // certificate issued, or issuance failed
	AuditDirectFetch   = "direct_fetch"      // direct-mode fetch served or refused
	AuditDNSPresent    = "dns_present"       // DNS proxy present
	AuditDNSCleanup    = "dns_cleanup"       // DNS proxy cleanup
	AuditLogin         = "login"             // login success or failure
	AuditLogout        = "logout"            // logout
	AuditGrantChange   = "grant_change"      // grant created, updated or deleted
	AuditUserChange    = "user_change"       // role or blocked flag changed
	AuditConfigChange  = "config_change"     // generation activated, rolled back; secret set
	AuditRateLimit     = "rate_limit"        // local or upstream rate-limit event
	AuditProviderState = "provider_state"    // provider circuit opened or closed
	AuditFailover      = "provider_failover" // emergency or new-issuance provider switch
	AuditError         = "error"             // LDAP, config or internal error worth attention
)

// Values of AuditEvent.Decision, AuditEvent.Result and AuditEvent.Visibility.
const (
	AuditDecisionAllow = "allow"
	AuditDecisionDeny  = "deny"

	AuditResultOK     = "ok"
	AuditResultDenied = "denied"
	AuditResultFailed = "failed"

	AuditVisibilityAll   = "public" // every logged-in user may see it
	AuditVisibilityAdmin = "admin"  // admins only
)

// AuditEvent is one line of the audit log (architecture §14). Unused fields
// are left zero and omitted from the JSON line.
type AuditEvent struct {
	// Time is filled in by the Auditor from its clock when zero.
	Time time.Time `json:"time"`
	Type string    `json:"type"` // one of the Audit* event types
	// Visibility is AuditVisibilityAll or AuditVisibilityAdmin; empty means
	// admin. Denied requests, grant/role/block changes, LDAP/config errors,
	// rate-limit events and failover are admin-only.
	Visibility string `json:"visibility,omitempty"`
	Mode       Mode   `json:"mode,omitempty"`
	SourceIP   string `json:"source_ip,omitempty"`
	// Names is the identifier set involved, normalized.
	Names    []string `json:"names,omitempty"`
	Decision string   `json:"decision,omitempty"` // allow | deny
	Reason   string   `json:"reason,omitempty"`   // a Reason constant
	Provider string   `json:"provider,omitempty"`
	Result   string   `json:"result,omitempty"` // ok | denied | failed
	// CertNotAfter is the expiry of the certificate issued or served.
	CertNotAfter *time.Time `json:"cert_not_after,omitempty"`
	// Username is set only for human control-plane actions.
	Username string `json:"username,omitempty"`
	// GrantID is set only when that grant caused the authorization.
	GrantID       int64  `json:"grant_id,omitempty"`
	OrderID       string `json:"order_id,omitempty"`
	CertificateID string `json:"certificate_id,omitempty"`
	// Detail is free text for operators; never secrets.
	Detail string `json:"detail,omitempty"`
}
