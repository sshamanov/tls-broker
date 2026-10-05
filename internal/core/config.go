package core

import (
	"context"
	"net/netip"
	"slices"
	"time"

	"tls-broker/internal/names"
)

// Config is the read-only view of the active configuration that packages
// consume. internal/config builds it from the current YAML generation, the
// environment and defaults; nobody else constructs one outside tests.
//
// A *Config is immutable once published: never modify one obtained from a
// ConfigSource. Durations are always positive unless documented otherwise;
// internal/config rejects or defaults anything else, so consumers do not
// re-validate.
type Config struct {
	// Generation is the number of the active configuration generation
	// (1 for <data>/config/000001.yaml).
	Generation int
	// DataDir is the data root (TLS_BROKER_DATA_DIR), an absolute path.
	DataDir string

	Server    ServerConfig
	Bootstrap BootstrapConfig
	Zones     []ZoneConfig
	Route53   Route53Config
	// Providers in order of preference: the first enabled provider is the
	// primary, the rest are fallbacks in order.
	Providers []ProviderConfig
	LDAP      LDAPConfig
	Sessions  SessionConfig
	Scheduler SchedulerConfig
	Emergency EmergencyConfig
	Direct    DirectConfig
	DNSProxy  DNSProxyConfig
	Upstream  UpstreamConfig
	Resolver  ResolverConfig
	Audit     AuditConfig
	// CTInventory configures the Certificate Transparency inventory
	// (architecture §31).
	CTInventory CTInventoryConfig
}

// ServerConfig holds listener and proxy settings (architecture §19, §21).
type ServerConfig struct {
	// Listen is the TCP listen address, "host:port" (TLS_BROKER_LISTEN).
	Listen string
	// ExternalURL is the base URL clients use, without trailing slash, for
	// example "https://broker.example.com". ACME URLs are built from it.
	ExternalURL string
	// TrustedProxies lists the peers (normally local nginx) whose
	// RealIPHeader is believed. Empty means no header is ever trusted.
	TrustedProxies []netip.Prefix
	// RealIPHeader is the single header carrying the client address when
	// the TCP peer is a trusted proxy, for example "X-Real-IP". It must
	// hold exactly one IPv4 address; X-Forwarded-For chains are not parsed.
	RealIPHeader string
	// ReadTimeout bounds reading one request; WriteTimeout bounds one
	// response and must exceed the longest held request (admission wait,
	// direct-mode synchronous issuance).
	ReadTimeout  time.Duration
	WriteTimeout time.Duration
	// ShutdownGrace is how long in-flight requests get on shutdown.
	ShutdownGrace time.Duration
}

// BootstrapConfig carries the environment-driven administrators
// (architecture §4.3). It never appears in YAML.
type BootstrapConfig struct {
	// Admins are LDAP usernames (lower case) that receive the admin role
	// at every login (TLS_BROKER_ADMINS).
	Admins []string
	// LocalAdminUser enables the break-glass admin when non-empty.
	LocalAdminUser string
	// LocalAdminPassword is the plain password or a bcrypt hash (a value
	// starting with "$2"), as given in the environment.
	LocalAdminPassword string
}

// ZoneConfig is one managed Route53 zone.
type ZoneConfig struct {
	Name         string // normalized zone name, for example "example.com"
	HostedZoneID string // Route53 hosted zone ID, for example "Z123ABC"; empty: discovered by name (dns01)
}

// Route53Config configures the DNS-01 engine (architecture §17).
type Route53Config struct {
	Region string
	// AccessKeyIDSecret / SecretAccessKeySecret name entries in the
	// SecretStore. When either is empty the standard AWS credential chain
	// is used.
	AccessKeyIDSecret     string
	SecretAccessKeySecret string
	// TTL of challenge TXT records.
	TTL time.Duration
	// ChangeTimeout bounds one Route53 change (submit until INSYNC).
	ChangeTimeout time.Duration
	// PropagationTimeout bounds the wait for the value to be visible
	// through the public resolver after the change is in sync.
	PropagationTimeout time.Duration
	// PollInterval is the pause between visibility checks.
	PollInterval time.Duration
}

// Limit is a sliding-window budget: at most Count events in any Window.
// Count 0 means the budget is not enforced.
type Limit struct {
	Count  int
	Window time.Duration
}

// ProviderLimits are the local budgets kept below one provider's real limits
// (architecture §10).
type ProviderLimits struct {
	NewOrders      Limit // upstream newOrder calls per account
	CertsPerDomain Limit // certificates per registered domain
	CertsPerSet    Limit // certificates per exact identifier set
	// Concurrency is the number of upstream preparations (order + DNS-01)
	// that may run at once. At least 1.
	Concurrency int
	// RenewalReservePercent (0..90) is the share of every budget's Count
	// that only renewals may use: a non-renewal is refused once usage
	// reaches Count*(100-RenewalReservePercent)/100, rounded down but
	// never below 1.
	RenewalReservePercent int
}

// ProviderConfig defines one upstream CA account.
type ProviderConfig struct {
	// Name is the stable local name ("letsencrypt"); it is stored with
	// orders and certificates and must not be reused for a different CA.
	Name     string
	Disabled bool // defined but not used for new issuance or renewal
	// DirectoryURL is the ACME directory.
	DirectoryURL string
	// Contact is the account e-mail address, optional.
	Contact string
	// EABKeyID / EABSecretName configure external account binding; both
	// empty when the CA does not need it. EABSecretName names an entry in
	// the SecretStore holding the base64url HMAC key.
	EABKeyID      string
	EABSecretName string
	// Profile is the ACME profile requested in newOrder; empty for the
	// CA's default.
	Profile string
	// CAAIssuers are the CAA issuer domain names that authorize this CA
	// ("letsencrypt.org"; "pki.goog").
	CAAIssuers []string
	// AccountURIHonoured says the CA enforces the RFC 8657 `accounturi`
	// CAA parameter. Only then can a CAA record naming this CA protect a
	// wildcard in DNS-proxy mode (architecture §3.2).
	AccountURIHonoured bool
	// ARI says the CA serves renewal information and accepts `replaces`.
	ARI bool
	// ARIExempt says a `replaces` order placed inside the suggested window
	// is exempt from the CA's rate limits (Let's Encrypt: true).
	ARIExempt bool
	Limits    ProviderLimits
}

// LDAPConfig configures human authentication (architecture §5). LDAP is
// "not configured" when URL is empty; logins then work only for the local
// break-glass admin.
type LDAPConfig struct {
	URL    string // ldaps://host:636 or ldap://host:389
	BindDN string
	// BindPasswordSecret names the SecretStore entry with the bind
	// password.
	BindPasswordSecret string
	BaseDN             string
	// UserFilter is the search filter with "%s" replaced by the escaped
	// username, for example "(&(objectClass=person)(uid=%s))". The user
	// must match it to log in.
	UserFilter string
	StartTLS   bool // upgrade an ldap:// connection with StartTLS
	// InsecureSkipVerify disables server certificate verification.
	InsecureSkipVerify bool
	Timeout            time.Duration // per LDAP operation
}

// SessionConfig configures UI sessions.
type SessionConfig struct {
	TTL          time.Duration // lifetime of a session from login
	CookieName   string
	CookieSecure CookieSecureMode // when the cookie gets the Secure attribute
}

// CookieSecureMode says when the session cookie carries the Secure
// attribute. The zero value is CookieSecureAuto.
type CookieSecureMode string

const (
	// CookieSecureAuto: Secure when the login request arrived over HTTPS
	// (directly, or through a trusted proxy that says so); a plain-HTTP
	// deployment then works without configuration.
	CookieSecureAuto CookieSecureMode = "auto"
	// CookieSecureAlways: Secure on every cookie. Over plain HTTP the
	// browser drops it and every login appears to fail.
	CookieSecureAlways CookieSecureMode = "always"
	// CookieSecureNever: never Secure, even behind TLS.
	CookieSecureNever CookieSecureMode = "never"
)

// Secure resolves the mode for a request that arrived over HTTPS or not.
func (m CookieSecureMode) Secure(https bool) bool {
	switch m {
	case CookieSecureAlways:
		return true
	case CookieSecureNever:
		return false
	}
	return https
}

// Valid reports whether m is one of the three modes (the empty string counts
// as auto).
func (m CookieSecureMode) Valid() bool {
	switch m {
	case "", CookieSecureAuto, CookieSecureAlways, CookieSecureNever:
		return true
	}
	return false
}

// SchedulerConfig holds the admission and order timing knobs.
type SchedulerConfig struct {
	// AdmitWait is how long newOrder (and a direct-mode request) may wait
	// for a concurrency slot before being refused as busy. Default 20 s.
	AdmitWait time.Duration
	// FinalizeWait is how long finalize holds the request for preparation
	// and issuance before answering "processing". Default 20 s.
	FinalizeWait time.Duration
	// OrderTTL is the life of an order that is never finalized. Default
	// 15 min.
	OrderTTL time.Duration
	// BusyRetryAfter is the Retry-After given when no slot became free.
	BusyRetryAfter time.Duration
	// ProcessingRetryAfter is the Retry-After given with a "processing"
	// order.
	ProcessingRetryAfter time.Duration
	// DownRetryAfter is how long a provider's circuit stays open after an
	// outage signal without Retry-After; it doubles with consecutive
	// failures up to DownRetryAfterMax.
	DownRetryAfter    time.Duration
	DownRetryAfterMax time.Duration
	// RateLimitRetryAfter is used when a provider rate-limits without
	// saying for how long.
	RateLimitRetryAfter time.Duration
}

// EmergencyConfig holds the emergency-window parameters (architecture §8).
type EmergencyConfig struct {
	Fraction     float64 // share of the certificate lifetime; default 0.05
	SafetyChecks int     // number of client check intervals; default 3
	// DefaultInterval is the check interval assumed for a lineage until
	// two requests have been seen; default 24 h.
	DefaultInterval time.Duration
}

// DirectConfig configures the direct certificate cache (architecture §11).
type DirectConfig struct {
	// RenewFraction is the share of the certificate lifetime after which
	// renewal is due when the provider gives no ARI window; default 2/3.
	RenewFraction float64
	// ARIPollInterval is how often renewal information is re-read for an
	// entry that is being fetched.
	ARIPollInterval time.Duration
	// IssueTimeout bounds one synchronous issuance (cache miss or expired
	// certificate) before the request gets 503.
	IssueTimeout time.Duration
	// RetryBackoff is the minimum pause between failed issuance attempts
	// for one identifier; it doubles with consecutive failures up to
	// RetryBackoffMax.
	RetryBackoff    time.Duration
	RetryBackoffMax time.Duration
	// RSABits is the key size of generated keys; default 2048.
	RSABits int
}

// DNSProxyConfig configures /dns/present and /dns/cleanup.
type DNSProxyConfig struct {
	// PresentTimeout bounds one present call including propagation.
	PresentTimeout time.Duration
	// ChallengeTTL is how long a presented value may stay before the
	// broker removes it on its own.
	ChallengeTTL time.Duration
	// MaxPerSource limits challenge creation per source address:
	// MaxPerSource.Count presents in any MaxPerSource.Window.
	MaxPerSource Limit
}

// UpstreamConfig holds the timeouts of upstream CA interaction, shared by all
// providers.
type UpstreamConfig struct {
	HTTPTimeout time.Duration // one HTTP request to a CA
	// ValidationTimeout bounds WaitReady: accept until the order is ready.
	ValidationTimeout time.Duration
	// IssueTimeout bounds WaitCertificate: finalize until the chain is
	// downloaded.
	IssueTimeout time.Duration
	// PollInterval is the pause between polls when the CA gives no
	// Retry-After.
	PollInterval time.Duration
	// PrepareTimeout bounds the whole background preparation of one order.
	PrepareTimeout time.Duration
}

// ResolverConfig holds the DoH client settings. The resolver endpoints are
// fixed (architecture §16) and not configurable.
type ResolverConfig struct {
	Timeout      time.Duration // one DoH request
	MaxCNAMEHops int           // CNAME chain limit; default 8
}

// AuditConfig configures the JSONL audit log.
type AuditConfig struct {
	MaxFileBytes int64 // rotate when the current file exceeds this size
	MaxFiles     int   // rotated files kept; 0 keeps all
}

// CTInventoryConfig configures the Certificate Transparency inventory of
// the managed zones (architecture §31).
type CTInventoryConfig struct {
	// Disabled switches the inventory off: no CT queries at all.
	Disabled bool
	// Interval is the pause between two refreshes; default
	// DefaultCTInterval, never below CTMinInterval for the zones queried.
	Interval time.Duration
}

// DefaultCTInterval is the default CT refresh interval: 2.5 times
// CTMinInterval for four queried zones.
const DefaultCTInterval = 4 * time.Hour

// CTQueriesPerHour is the CT source's unauthenticated limit of queries that
// include subdomains (SSLMate Cert Spotter: 10 "full-domain queries" per
// hour per client, October 2026). Every page counts, the final empty page
// included.
const CTQueriesPerHour = 10

// CTMinInterval is the shortest CT refresh interval allowed for the given
// number of queried zones. A routine refresh continues from the source's
// cursor and costs at most two queries per zone (a page of new issuances
// and the final empty page); routine refreshes may use at most half of
// CTQueriesPerHour, so the other half stays free for the full fetch after a
// restart and for retries. That is zones*2 queries per interval <=
// CTQueriesPerHour/2 per hour, i.e. 24 minutes per zone, and never less
// than an hour.
func CTMinInterval(zones int) time.Duration {
	return max(time.Duration(zones)*2*time.Hour/(CTQueriesPerHour/2), time.Hour)
}

// DefaultConfig returns a configuration with every default filled in and no
// zones, no providers and no LDAP. internal/config starts from it; tests use
// it as a base.
func DefaultConfig() *Config {
	return &Config{
		Generation: 1,
		DataDir:    "/var/lib/tls-broker",
		Server: ServerConfig{
			Listen:        "127.0.0.1:8080",
			ExternalURL:   "http://127.0.0.1:8080",
			RealIPHeader:  "X-Real-IP",
			ReadTimeout:   30 * time.Second,
			WriteTimeout:  5 * time.Minute,
			ShutdownGrace: 25 * time.Second,
		},
		Route53: Route53Config{
			Region:             "us-east-1",
			TTL:                60 * time.Second,
			ChangeTimeout:      2 * time.Minute,
			PropagationTimeout: 2 * time.Minute,
			PollInterval:       2 * time.Second,
		},
		LDAP:     LDAPConfig{Timeout: 10 * time.Second},
		Sessions: SessionConfig{TTL: 30 * 24 * time.Hour, CookieName: "tls_broker_session", CookieSecure: CookieSecureAuto},
		Scheduler: SchedulerConfig{
			AdmitWait:            20 * time.Second,
			FinalizeWait:         20 * time.Second,
			OrderTTL:             15 * time.Minute,
			BusyRetryAfter:       30 * time.Second,
			ProcessingRetryAfter: 3 * time.Second,
			DownRetryAfter:       time.Minute,
			DownRetryAfterMax:    30 * time.Minute,
			RateLimitRetryAfter:  time.Hour,
		},
		Emergency: EmergencyConfig{Fraction: 0.05, SafetyChecks: 3, DefaultInterval: 24 * time.Hour},
		Direct: DirectConfig{
			RenewFraction:   2.0 / 3.0,
			ARIPollInterval: 6 * time.Hour,
			IssueTimeout:    4 * time.Minute,
			RetryBackoff:    time.Minute,
			RetryBackoffMax: time.Hour,
			RSABits:         2048,
		},
		DNSProxy: DNSProxyConfig{
			PresentTimeout: 4 * time.Minute,
			ChallengeTTL:   time.Hour,
			MaxPerSource:   Limit{Count: 30, Window: time.Hour},
		},
		Upstream: UpstreamConfig{
			HTTPTimeout:       30 * time.Second,
			ValidationTimeout: 2 * time.Minute,
			IssueTimeout:      2 * time.Minute,
			PollInterval:      2 * time.Second,
			PrepareTimeout:    10 * time.Minute,
		},
		Resolver:    ResolverConfig{Timeout: 5 * time.Second, MaxCNAMEHops: 8},
		Audit:       AuditConfig{MaxFileBytes: 50 << 20, MaxFiles: 0},
		CTInventory: CTInventoryConfig{Interval: DefaultCTInterval},
	}
}

// DefaultProviderLimits are conservative budgets below Let's Encrypt's
// published limits (300 new orders / 3 h, 50 certificates / registered domain
// / 7 d, 5 / exact set / 7 d); a sensible start for any provider.
func DefaultProviderLimits() ProviderLimits {
	return ProviderLimits{
		NewOrders:             Limit{Count: 200, Window: 3 * time.Hour},
		CertsPerDomain:        Limit{Count: 40, Window: 7 * 24 * time.Hour},
		CertsPerSet:           Limit{Count: 4, Window: 7 * 24 * time.Hour},
		Concurrency:           4,
		RenewalReservePercent: 25,
	}
}

// ManagedZones returns the managed zones as a matcher. A zone name that does
// not normalize is skipped (internal/config never publishes one).
func (c *Config) ManagedZones() names.Zones {
	list := make([]string, 0, len(c.Zones))
	for _, z := range c.Zones {
		if _, err := names.NewZones(z.Name); err == nil {
			list = append(list, z.Name)
		}
	}
	zs, _ := names.NewZones(list...)
	return zs
}

// CTZones returns the managed zones the CT inventory queries: every zone
// that is not inside another managed zone (a query for example.com with its
// subdomains also covers a managed dev.example.com), in sorted order.
func (c *Config) CTZones() []string {
	all := c.ManagedZones().List()
	var out []string
	for _, z := range all {
		inner := false
		for _, o := range all {
			if o != z && names.InZone(z, o) {
				inner = true
				break
			}
		}
		if !inner {
			out = append(out, z)
		}
	}
	slices.Sort(out)
	return out
}

// ZoneFor returns the managed zone holding the normalized name (longest
// suffix), or false when the name is outside every managed zone.
func (c *Config) ZoneFor(name string) (ZoneConfig, bool) {
	zone, ok := c.ManagedZones().Match(name)
	if !ok {
		return ZoneConfig{}, false
	}
	for _, z := range c.Zones {
		if n, err := names.Normalize(z.Name); err == nil && n == zone {
			return z, true
		}
	}
	return ZoneConfig{}, false
}

// Provider returns the provider definition with the given name (enabled or
// not).
func (c *Config) Provider(name string) (ProviderConfig, bool) {
	for _, p := range c.Providers {
		if p.Name == name {
			return p, true
		}
	}
	return ProviderConfig{}, false
}

// EnabledProviders returns the providers that are not disabled, in order of
// preference.
func (c *Config) EnabledProviders() []ProviderConfig {
	out := make([]ProviderConfig, 0, len(c.Providers))
	for _, p := range c.Providers {
		if !p.Disabled {
			out = append(out, p)
		}
	}
	return out
}

// TrustsProxy reports whether the TCP peer is a trusted proxy.
func (c *Config) TrustsProxy(peer netip.Addr) bool {
	peer = peer.Unmap()
	for _, p := range c.Server.TrustedProxies {
		if p.Contains(peer) {
			return true
		}
	}
	return false
}

// ConfigSource gives access to the active configuration without importing
// internal/config.
type ConfigSource interface {
	// Current returns the active configuration. It never returns nil and
	// is cheap; call it at the start of each operation rather than keeping
	// the pointer, so a reload takes effect.
	Current() *Config
	// Subscribe returns a channel that receives a value after the active
	// configuration changes, and a cancel function that releases the
	// subscription (and closes the channel). The channel has capacity 1
	// and notifications coalesce: after receiving, call Current. Nothing
	// is sent for the configuration that was active at Subscribe time.
	Subscribe() (changed <-chan struct{}, cancel func())
}

// ConfigGeneration describes one stored configuration generation.
type ConfigGeneration struct {
	Number    int
	Active    bool
	CreatedAt time.Time
}

// ConfigCheck is the result of validating a candidate configuration.
type ConfigCheck struct {
	// Errors are problems that prevent activation; empty means valid.
	Errors []string
	// Warnings do not prevent activation (for example a zone without CAA).
	Warnings []string
	// LDAPTested is true when the candidate has LDAP settings and they
	// were tested; LDAPError is the failure, empty on success. A failed
	// LDAP test is also listed in Errors.
	LDAPTested bool
	LDAPError  string
}

// OK reports whether the candidate may be activated.
func (c ConfigCheck) OK() bool { return len(c.Errors) == 0 }

// ConfigAdmin is the editing surface of the configuration, implemented by
// internal/config and used by the UI (architecture §15).
type ConfigAdmin interface {
	// Generations lists stored generations, newest first.
	Generations(ctx context.Context) ([]ConfigGeneration, error)
	// Read returns the YAML of a generation; ErrNotFound if it does not
	// exist.
	Read(ctx context.Context, number int) ([]byte, error)
	// Validate checks candidate YAML (syntax, zones, providers, LDAP test)
	// without storing anything. The error is non-nil only when validation
	// itself could not run.
	Validate(ctx context.Context, yaml []byte) (ConfigCheck, error)
	// Activate validates, stores the YAML as the next generation, makes it
	// current and notifies subscribers. When validation fails nothing is
	// stored and the returned check has !OK() with a nil error.
	Activate(ctx context.Context, yaml []byte) (number int, check ConfigCheck, err error)
	// Rollback makes an existing generation current again (after
	// re-validating it without the LDAP test) and notifies subscribers.
	// ErrNotFound if it does not exist.
	Rollback(ctx context.Context, number int) error
}

// SecretStore holds service credentials under <data>/secrets, by name. Names
// match [a-z0-9][a-z0-9._-]*. Implemented by internal/config.
type SecretStore interface {
	// Get returns the secret value; ErrNotFound if it is not set.
	Get(ctx context.Context, name string) ([]byte, error)
	// Put creates or replaces a secret (file mode 0600, written
	// atomically).
	Put(ctx context.Context, name string, value []byte) error
	// Delete removes a secret; deleting a missing secret is not an error.
	Delete(ctx context.Context, name string) error
	// List returns the names of all secrets, sorted. Values are never
	// listed.
	List(ctx context.Context) ([]string, error)
}

// Names of secrets written by the broker itself.
const (
	// SecretProviderAccountKeyPrefix + provider name holds the upstream
	// account private key (PEM, PKCS#8).
	SecretProviderAccountKeyPrefix = "provider-account-key."
	// SecretProviderAccountURLPrefix + provider name holds the upstream
	// account URL once registered.
	SecretProviderAccountURLPrefix = "provider-account-url."
)
