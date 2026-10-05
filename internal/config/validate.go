package config

import (
	"fmt"
	"net/mail"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/go-ldap/ldap/v3"

	"tls-broker/internal/core"
	"tls-broker/internal/names"
)

var (
	secretNameRe   = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]*$`)
	providerNameRe = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,63}$`)
	hostedZoneRe   = regexp.MustCompile(`^Z[A-Z0-9]{1,31}$`)
	regionRe       = regexp.MustCompile(`^[a-z]{2}(-[a-z]+)+-[0-9]$`)
	headerRe       = regexp.MustCompile("^[!#$%&'*+.^_`|~0-9A-Za-z-]+$")
	cookieNameRe   = regexp.MustCompile(`^[A-Za-z0-9_-]+$`)
)

// MaxSecretNameLen is the longest secret name.
const MaxSecretNameLen = 128

// ValidSecretName reports whether name is a legal secret name:
// [a-z0-9][a-z0-9._-]*, at most MaxSecretNameLen bytes.
func ValidSecretName(name string) bool {
	return len(name) <= MaxSecretNameLen && secretNameRe.MatchString(name)
}

// Validate applies every semantic rule to cfg and returns all findings at
// once. Paths are YAML field paths. It does not touch the file system, the
// network or the secret store.
func Validate(cfg *core.Config) Report {
	v := &validator{cfg: cfg}
	v.server()
	v.zones()
	v.route53()
	v.providers()
	v.ldap()
	v.sessions()
	v.scheduler()
	v.emergency()
	v.direct()
	v.dnsProxy()
	v.upstream()
	v.resolver()
	v.audit()
	v.ctInventory()
	v.crossChecks()
	return Report{Errors: v.problems, Warnings: v.warnings}
}

// ValidateLDAP applies only the LDAP rules; it is used to decide whether the
// LDAP test can run on an otherwise broken candidate.
func ValidateLDAP(l core.LDAPConfig) Problems {
	c := &core.Config{LDAP: l}
	v := &validator{cfg: c}
	v.ldap()
	return v.problems
}

type validator struct {
	collector
	cfg *core.Config
}

// rng checks lo <= d <= hi.
func (v *validator) rng(path string, d, lo, hi time.Duration) {
	if d < lo || d > hi {
		v.errf(path, "must be between %s and %s, got %s", FormatDuration(lo), FormatDuration(hi), FormatDuration(d))
	}
}

func (v *validator) intRng(path string, n, lo, hi int) {
	if n < lo || n > hi {
		v.errf(path, "must be between %d and %d, got %d", lo, hi, n)
	}
}

func (v *validator) limit(path string, l core.Limit) {
	if l.Count < 0 {
		v.errf(path+".count", "must not be negative, got %d", l.Count)
	}
	if l.Count > 0 {
		v.rng(path+".window", l.Window, time.Second, 366*24*time.Hour)
	} else if l.Window < 0 {
		v.errf(path+".window", "must not be negative")
	}
}

func (v *validator) secretRef(path, name string) {
	if name == "" {
		return
	}
	switch {
	case !ValidSecretName(name):
		v.errf(path, "%q is not a valid secret name (lower-case letters, digits, '.', '_' and '-', starting with a letter or digit, at most %d characters)", name, MaxSecretNameLen)
	case strings.HasPrefix(name, core.SecretProviderAccountKeyPrefix) || strings.HasPrefix(name, core.SecretProviderAccountURLPrefix):
		v.errf(path, "%q is reserved for broker-generated provider account data", name)
	}
}

func (v *validator) server() {
	s := v.cfg.Server
	if s.ExternalURL == "" {
		v.errf("server.external_url", "is required")
	} else if u, err := url.Parse(s.ExternalURL); err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.Hostname() == "" {
		v.errf("server.external_url", "must be an http(s) URL such as https://broker.example.com")
	} else if u.RawQuery != "" || u.Fragment != "" || u.User != nil {
		v.errf("server.external_url", "must not contain user info, query or fragment")
	} else if u.Scheme == "http" {
		v.warnf("server.external_url", "uses http; ACME clients require https")
	}
	if len(s.TrustedProxies) > 0 && s.RealIPHeader == "" {
		v.errf("server.real_ip_header", "is required when trusted_proxies is not empty")
	}
	if s.RealIPHeader != "" && !headerRe.MatchString(s.RealIPHeader) {
		v.errf("server.real_ip_header", "%q is not a valid HTTP header name", s.RealIPHeader)
	}
	if strings.EqualFold(s.RealIPHeader, "X-Forwarded-For") {
		v.errf("server.real_ip_header", "X-Forwarded-For chains are not parsed; use a header that holds exactly one address, such as X-Real-IP")
	}
	for i, p := range s.TrustedProxies {
		if p.Bits() == 0 {
			v.errf(fmt.Sprintf("server.trusted_proxies[%d]", i), "%s would trust every peer", p)
		}
	}
	v.rng("server.read_timeout", s.ReadTimeout, time.Second, 10*time.Minute)
	v.rng("server.write_timeout", s.WriteTimeout, time.Second, time.Hour)
	v.rng("server.shutdown_grace", s.ShutdownGrace, time.Second, 10*time.Minute)
	if s.WriteTimeout < s.ReadTimeout {
		v.errf("server.write_timeout", "must not be shorter than read_timeout")
	}
}

func (v *validator) zones() {
	seen := map[string]int{}
	ids := map[string]int{}
	for i, z := range v.cfg.Zones {
		p := fmt.Sprintf("zones[%d]", i)
		n, err := names.Normalize(z.Name)
		switch {
		case z.Name == "":
			v.errf(p+".name", "is required")
		case err != nil:
			v.errf(p+".name", "%q is not a valid zone name: %v", z.Name, err)
		case names.IsWildcard(n):
			v.errf(p+".name", "%q: a zone name must not be a wildcard", z.Name)
		case n != z.Name:
			v.errf(p+".name", "%q is not in normalized form; write %q", z.Name, n)
		default:
			if j, dup := seen[n]; dup {
				v.errf(p+".name", "%q duplicates zones[%d]", n, j)
			}
			seen[n] = i
		}
		// hosted_zone_id is optional: an empty one is discovered by name
		// through ListHostedZones when the configuration is applied.
		switch {
		case z.HostedZoneID == "":
		case !hostedZoneRe.MatchString(z.HostedZoneID):
			v.errf(p+".hosted_zone_id", "%q is not a Route53 hosted zone ID (like Z0123456789ABCDEFGHIJ, without a /hostedzone/ prefix)", z.HostedZoneID)
		default:
			if j, dup := ids[z.HostedZoneID]; dup {
				v.warnf(p+".hosted_zone_id", "%s is also used by zones[%d]", z.HostedZoneID, j)
			}
			ids[z.HostedZoneID] = i
		}
	}
	if len(v.cfg.Zones) == 0 {
		v.warnf("zones", "no managed zones configured; every name is refused")
	}
}

func (v *validator) route53() {
	r := v.cfg.Route53
	if !regionRe.MatchString(r.Region) {
		v.errf("route53.region", "%q is not an AWS region such as us-east-1", r.Region)
	}
	if (r.AccessKeyIDSecret == "") != (r.SecretAccessKeySecret == "") {
		v.errf("route53.access_key_id_secret", "access_key_id_secret and secret_access_key_secret must be set together (or both empty to use the AWS credential chain)")
	}
	v.secretRef("route53.access_key_id_secret", r.AccessKeyIDSecret)
	v.secretRef("route53.secret_access_key_secret", r.SecretAccessKeySecret)
	v.rng("route53.ttl", r.TTL, time.Second, 24*time.Hour)
	if r.TTL%time.Second != 0 {
		v.errf("route53.ttl", "must be a whole number of seconds")
	}
	v.rng("route53.change_timeout", r.ChangeTimeout, time.Second, time.Hour)
	v.rng("route53.propagation_timeout", r.PropagationTimeout, time.Second, time.Hour)
	v.rng("route53.poll_interval", r.PollInterval, 100*time.Millisecond, 5*time.Minute)
	if r.PollInterval > r.PropagationTimeout {
		v.errf("route53.poll_interval", "must not exceed propagation_timeout")
	}
}

func (v *validator) providers() {
	seen := map[string]int{}
	enabled := 0
	for i, pr := range v.cfg.Providers {
		p := fmt.Sprintf("providers[%d]", i)
		if !pr.Disabled {
			enabled++
		}
		switch {
		case pr.Name == "":
			v.errf(p+".name", "is required")
		case !providerNameRe.MatchString(pr.Name):
			v.errf(p+".name", "%q must be 1-64 characters of lower-case letters, digits, '_' and '-', starting with a letter or digit", pr.Name)
		default:
			if j, dup := seen[pr.Name]; dup {
				v.errf(p+".name", "%q duplicates providers[%d]", pr.Name, j)
			}
			seen[pr.Name] = i
		}
		if u, err := url.Parse(pr.DirectoryURL); pr.DirectoryURL == "" {
			v.errf(p+".directory_url", "is required")
		} else if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil {
			v.errf(p+".directory_url", "must be an https URL, got %q", pr.DirectoryURL)
		}
		if pr.Contact != "" {
			if a, err := mail.ParseAddress(pr.Contact); err != nil || a.Address != pr.Contact {
				v.errf(p+".contact", "%q is not a plain e-mail address", pr.Contact)
			}
		}
		if (pr.EABKeyID == "") != (pr.EABSecretName == "") {
			v.errf(p+".eab_key_id", "eab_key_id and eab_secret must be set together")
		}
		v.secretRef(p+".eab_secret", pr.EABSecretName)
		if strings.ContainsAny(pr.Profile, " \t\r\n") {
			v.errf(p+".profile", "must not contain whitespace")
		}
		if len(pr.CAAIssuers) == 0 && !pr.Disabled {
			v.errf(p+".caa_issuers", "at least one CAA issuer domain is required (for example letsencrypt.org)")
		}
		for j, ci := range pr.CAAIssuers {
			if n, err := names.Normalize(ci); err != nil || n != ci || names.IsWildcard(n) {
				v.errf(fmt.Sprintf("%s.caa_issuers[%d]", p, j), "%q is not a valid issuer domain name", ci)
			}
		}
		if pr.ARIExempt && !pr.ARI {
			v.errf(p+".ari_exempt", "requires ari: true")
		}
		l := pr.Limits
		v.limit(p+".limits.new_orders", l.NewOrders)
		v.limit(p+".limits.certs_per_domain", l.CertsPerDomain)
		v.limit(p+".limits.certs_per_set", l.CertsPerSet)
		v.intRng(p+".limits.concurrency", l.Concurrency, 1, 64)
		v.intRng(p+".limits.renewal_reserve_percent", l.RenewalReservePercent, 0, 90)
	}
	if len(v.cfg.Providers) > 0 && enabled == 0 {
		v.errf("providers", "at least one provider must be enabled; the first enabled provider is the primary")
	}
	if len(v.cfg.Providers) == 0 {
		v.warnf("providers", "no upstream providers configured; no certificate can be issued")
	}
}

func (v *validator) ldap() {
	l := v.cfg.LDAP
	if l.URL == "" {
		if l.BindDN != "" || l.BindPasswordSecret != "" || l.BaseDN != "" || l.UserFilter != "" || l.StartTLS || l.InsecureSkipVerify {
			v.errf("ldap.url", "is required when any other LDAP setting is present (leave all LDAP settings empty to disable LDAP)")
		}
		return
	}
	u, err := url.Parse(l.URL)
	switch {
	case err != nil || u.Hostname() == "" || (u.Scheme != "ldap" && u.Scheme != "ldaps"):
		v.errf("ldap.url", "must look like ldaps://host:636 or ldap://host:389, got %q", l.URL)
	case u.Path != "" && u.Path != "/" || u.RawQuery != "" || u.User != nil:
		v.errf("ldap.url", "must contain only scheme, host and port")
	case u.Scheme == "ldaps" && l.StartTLS:
		v.errf("ldap.starttls", "cannot be combined with an ldaps:// URL")
	case u.Scheme == "ldap" && !l.StartTLS:
		v.warnf("ldap.url", "ldap:// without starttls sends passwords in clear text")
	}
	if l.InsecureSkipVerify {
		v.warnf("ldap.insecure_skip_verify", "server certificate verification is disabled")
	}
	if (l.BindDN == "") != (l.BindPasswordSecret == "") {
		v.errf("ldap.bind_dn", "bind_dn and bind_password_secret must be set together (or both empty for an anonymous search)")
	}
	if l.BindDN != "" {
		if _, err := ldap.ParseDN(l.BindDN); err != nil {
			v.errf("ldap.bind_dn", "is not a valid DN: %v", err)
		}
	}
	v.secretRef("ldap.bind_password_secret", l.BindPasswordSecret)
	if l.BaseDN == "" {
		v.errf("ldap.base_dn", "is required")
	} else if _, err := ldap.ParseDN(l.BaseDN); err != nil {
		v.errf("ldap.base_dn", "is not a valid DN: %v", err)
	}
	switch {
	case l.UserFilter == "":
		v.errf("ldap.user_filter", "is required, for example (&(objectClass=person)(uid=%%s))")
	case strings.Count(l.UserFilter, "%s") != 1:
		v.errf("ldap.user_filter", "must contain the username placeholder %%s exactly once")
	default:
		if _, err := ldap.CompileFilter(strings.Replace(l.UserFilter, "%s", "user", 1)); err != nil {
			v.errf("ldap.user_filter", "is not a valid LDAP filter: %v", err)
		}
	}
	v.rng("ldap.timeout", l.Timeout, time.Second, 2*time.Minute)
}

func (v *validator) sessions() {
	s := v.cfg.Sessions
	v.rng("sessions.ttl", s.TTL, 5*time.Minute, 365*24*time.Hour)
	if !cookieNameRe.MatchString(s.CookieName) {
		v.errf("sessions.cookie_name", "%q must consist of letters, digits, '_' and '-'", s.CookieName)
	}
	switch s.CookieSecure {
	case core.CookieSecureNever:
		v.warnf("sessions.cookie_secure", "never: session cookies are sent over plain http even behind TLS")
	case core.CookieSecureAuto, core.CookieSecureAlways:
	default:
		v.errf("sessions.cookie_secure", "%q must be auto, always or never", string(s.CookieSecure))
	}
}

func (v *validator) scheduler() {
	s := v.cfg.Scheduler
	v.rng("scheduler.admit_wait", s.AdmitWait, time.Second, 5*time.Minute)
	v.rng("scheduler.finalize_wait", s.FinalizeWait, time.Second, 5*time.Minute)
	v.rng("scheduler.order_ttl", s.OrderTTL, time.Minute, 24*time.Hour)
	v.rng("scheduler.busy_retry_after", s.BusyRetryAfter, time.Second, time.Hour)
	v.rng("scheduler.processing_retry_after", s.ProcessingRetryAfter, time.Second, 5*time.Minute)
	v.rng("scheduler.down_retry_after", s.DownRetryAfter, time.Second, 24*time.Hour)
	v.rng("scheduler.down_retry_after_max", s.DownRetryAfterMax, time.Second, 7*24*time.Hour)
	v.rng("scheduler.rate_limit_retry_after", s.RateLimitRetryAfter, time.Second, 7*24*time.Hour)
	if s.DownRetryAfter > s.DownRetryAfterMax {
		v.errf("scheduler.down_retry_after", "must not exceed down_retry_after_max")
	}
}

func (v *validator) emergency() {
	e := v.cfg.Emergency
	if !(e.Fraction > 0 && e.Fraction <= 0.5) {
		v.errf("emergency.fraction", "must be greater than 0 and at most 0.5, got %v", e.Fraction)
	}
	v.intRng("emergency.safety_checks", e.SafetyChecks, 1, 20)
	v.rng("emergency.default_interval", e.DefaultInterval, time.Hour, 90*24*time.Hour)
}

func (v *validator) direct() {
	d := v.cfg.Direct
	if !(d.RenewFraction >= 0.1 && d.RenewFraction <= 0.95) {
		v.errf("direct.renew_fraction", "must be between 0.1 and 0.95, got %v", d.RenewFraction)
	}
	v.rng("direct.ari_poll_interval", d.ARIPollInterval, time.Minute, 7*24*time.Hour)
	v.rng("direct.issue_timeout", d.IssueTimeout, time.Second, time.Hour)
	v.rng("direct.retry_backoff", d.RetryBackoff, time.Second, 24*time.Hour)
	v.rng("direct.retry_backoff_max", d.RetryBackoffMax, time.Second, 7*24*time.Hour)
	if d.RetryBackoff > d.RetryBackoffMax {
		v.errf("direct.retry_backoff", "must not exceed retry_backoff_max")
	}
	if d.RSABits != 2048 && d.RSABits != 3072 && d.RSABits != 4096 {
		v.errf("direct.rsa_bits", "must be 2048, 3072 or 4096, got %d", d.RSABits)
	}
}

func (v *validator) dnsProxy() {
	d := v.cfg.DNSProxy
	v.rng("dns_proxy.present_timeout", d.PresentTimeout, time.Second, time.Hour)
	v.rng("dns_proxy.challenge_ttl", d.ChallengeTTL, time.Minute, 24*time.Hour)
	if d.ChallengeTTL < d.PresentTimeout {
		v.errf("dns_proxy.challenge_ttl", "must not be shorter than present_timeout")
	}
	v.limit("dns_proxy.max_per_source", d.MaxPerSource)
}

func (v *validator) upstream() {
	u := v.cfg.Upstream
	v.rng("upstream.http_timeout", u.HTTPTimeout, time.Second, 5*time.Minute)
	v.rng("upstream.validation_timeout", u.ValidationTimeout, time.Second, time.Hour)
	v.rng("upstream.issue_timeout", u.IssueTimeout, time.Second, time.Hour)
	v.rng("upstream.poll_interval", u.PollInterval, 100*time.Millisecond, time.Minute)
	v.rng("upstream.prepare_timeout", u.PrepareTimeout, time.Second, 6*time.Hour)
	if u.PrepareTimeout < u.ValidationTimeout {
		v.errf("upstream.prepare_timeout", "must not be shorter than validation_timeout")
	}
}

func (v *validator) resolver() {
	r := v.cfg.Resolver
	v.rng("resolver.timeout", r.Timeout, 100*time.Millisecond, time.Minute)
	v.intRng("resolver.max_cname_hops", r.MaxCNAMEHops, 1, 16)
}

// ctInventory keeps the CT refresh inside the source's unauthenticated
// query limit for the zones it queries (core.CTMinInterval).
func (v *validator) ctInventory() {
	c := v.cfg.CTInventory
	if c.Disabled {
		v.rng("ct_inventory.interval", c.Interval, time.Hour, 7*24*time.Hour)
		return
	}
	n := len(v.cfg.CTZones())
	floor := core.CTMinInterval(n)
	if c.Interval < floor {
		v.errf("ct_inventory.interval", "must be at least %s for %d queried zone(s): the CT source allows %d queries per hour without an account, and a refresh costs up to 2 per zone; got %s",
			FormatDuration(floor), n, core.CTQueriesPerHour, FormatDuration(c.Interval))
		return
	}
	v.rng("ct_inventory.interval", c.Interval, floor, 7*24*time.Hour)
}

func (v *validator) audit() {
	a := v.cfg.Audit
	if a.MaxFileBytes < 1<<20 {
		v.errf("audit.max_file_bytes", "must be at least 1048576 (1 MiB), got %d", a.MaxFileBytes)
	}
	if a.MaxFiles < 0 {
		v.errf("audit.max_files", "must not be negative (0 keeps every file)")
	}
}

// crossChecks covers rules that relate sections to each other.
func (v *validator) crossChecks() {
	c := v.cfg
	held := map[string]time.Duration{
		"scheduler.admit_wait":      c.Scheduler.AdmitWait,
		"scheduler.finalize_wait":   c.Scheduler.FinalizeWait,
		"direct.issue_timeout":      c.Direct.IssueTimeout,
		"dns_proxy.present_timeout": c.DNSProxy.PresentTimeout,
	}
	for _, k := range []string{"scheduler.admit_wait", "scheduler.finalize_wait", "direct.issue_timeout", "dns_proxy.present_timeout"} {
		if c.Server.WriteTimeout <= held[k] {
			v.errf("server.write_timeout", "must exceed %s (%s): a held request would be cut off", k, FormatDuration(held[k]))
		}
	}
	if c.Sessions.CookieSecure == core.CookieSecureAlways && strings.HasPrefix(c.Server.ExternalURL, "http://") {
		v.warnf("sessions.cookie_secure", "always while external_url is http: browsers will not send the cookie back")
	}
}

// CheckSecrets reports every secret name referenced by cfg that is not in
// have. The broker's own provider-account-* secrets are not referenced from
// the configuration and are not checked.
func CheckSecrets(cfg *core.Config, have []string) Problems {
	set := map[string]bool{}
	for _, n := range have {
		set[n] = true
	}
	var out Problems
	check := func(path, name string) {
		if name != "" && !set[name] {
			out = append(out, Problem{Path: path, Message: fmt.Sprintf("secret %q does not exist; set it first", name)})
		}
	}
	check("route53.access_key_id_secret", cfg.Route53.AccessKeyIDSecret)
	check("route53.secret_access_key_secret", cfg.Route53.SecretAccessKeySecret)
	for i, p := range cfg.Providers {
		check(fmt.Sprintf("providers[%d].eab_secret", i), p.EABSecretName)
	}
	check("ldap.bind_password_secret", cfg.LDAP.BindPasswordSecret)
	return out
}
