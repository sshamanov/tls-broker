package config

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"regexp"
	"slices"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"tls-broker/internal/core"
	"tls-broker/internal/names"
)

// The YAML model. Field names are the documented YAML keys. Process-level
// settings (data dir, listen address, bootstrap admins) are environment only
// and are deliberately absent: a YAML that names them is rejected as an
// unknown field.

type document struct {
	Server    serverDoc     `yaml:"server"`
	Zones     []zoneDoc     `yaml:"zones"`
	Route53   route53Doc    `yaml:"route53"`
	Providers []providerDoc `yaml:"providers"`
	LDAP      ldapDoc       `yaml:"ldap"`
	Sessions  sessionsDoc   `yaml:"sessions"`
	Scheduler schedulerDoc  `yaml:"scheduler"`
	Emergency emergencyDoc  `yaml:"emergency"`
	Direct    directDoc     `yaml:"direct"`
	DNSProxy  dnsProxyDoc   `yaml:"dns_proxy"`
	Upstream  upstreamDoc   `yaml:"upstream"`
	Resolver  resolverDoc   `yaml:"resolver"`
	Audit     auditDoc      `yaml:"audit"`
}

type serverDoc struct {
	ExternalURL    string   `yaml:"external_url"`
	TrustedProxies []string `yaml:"trusted_proxies"`
	RealIPHeader   string   `yaml:"real_ip_header"`
	ReadTimeout    Duration `yaml:"read_timeout"`
	WriteTimeout   Duration `yaml:"write_timeout"`
	ShutdownGrace  Duration `yaml:"shutdown_grace"`
}

type zoneDoc struct {
	Name            string   `yaml:"name"`
	HostedZoneID    string   `yaml:"hosted_zone_id"`
	TrustedAccounts []string `yaml:"trusted_accounts,omitempty"`
}

type route53Doc struct {
	Region                string   `yaml:"region"`
	AccessKeyIDSecret     string   `yaml:"access_key_id_secret"`
	SecretAccessKeySecret string   `yaml:"secret_access_key_secret"`
	TTL                   Duration `yaml:"ttl"`
	ChangeTimeout         Duration `yaml:"change_timeout"`
	PropagationTimeout    Duration `yaml:"propagation_timeout"`
	PollInterval          Duration `yaml:"poll_interval"`
}

type limitDoc struct {
	Count  int      `yaml:"count"`
	Window Duration `yaml:"window"`
}

// providerLimitsDoc uses pointers so an omitted limit takes the default
// (core.DefaultProviderLimits) while a present one must be complete.
type providerLimitsDoc struct {
	NewOrders             *limitDoc `yaml:"new_orders"`
	CertsPerDomain        *limitDoc `yaml:"certs_per_domain"`
	CertsPerSet           *limitDoc `yaml:"certs_per_set"`
	Concurrency           *int      `yaml:"concurrency"`
	RenewalReservePercent *int      `yaml:"renewal_reserve_percent"`
}

type providerDoc struct {
	Name               string            `yaml:"name"`
	Disabled           bool              `yaml:"disabled"`
	DirectoryURL       string            `yaml:"directory_url"`
	Contact            string            `yaml:"contact"`
	EABKeyID           string            `yaml:"eab_key_id"`
	EABSecret          string            `yaml:"eab_secret"`
	Profile            string            `yaml:"profile"`
	CAAIssuers         []string          `yaml:"caa_issuers"`
	AccountURIHonoured bool              `yaml:"account_uri_honoured"`
	ARI                bool              `yaml:"ari"`
	ARIExempt          bool              `yaml:"ari_exempt"`
	Limits             providerLimitsDoc `yaml:"limits"`
}

type ldapDoc struct {
	URL                string   `yaml:"url"`
	BindDN             string   `yaml:"bind_dn"`
	BindPasswordSecret string   `yaml:"bind_password_secret"`
	BaseDN             string   `yaml:"base_dn"`
	UserFilter         string   `yaml:"user_filter"`
	StartTLS           bool     `yaml:"starttls"`
	InsecureSkipVerify bool     `yaml:"insecure_skip_verify"`
	Timeout            Duration `yaml:"timeout"`
}

type sessionsDoc struct {
	TTL        Duration `yaml:"ttl"`
	CookieName string   `yaml:"cookie_name"`
	// CookieSecure is auto | always | never; the booleans true and false
	// of earlier generations are read as always and never.
	CookieSecure string `yaml:"cookie_secure"`
}

type schedulerDoc struct {
	AdmitWait            Duration `yaml:"admit_wait"`
	FinalizeWait         Duration `yaml:"finalize_wait"`
	OrderTTL             Duration `yaml:"order_ttl"`
	BusyRetryAfter       Duration `yaml:"busy_retry_after"`
	ProcessingRetryAfter Duration `yaml:"processing_retry_after"`
	DownRetryAfter       Duration `yaml:"down_retry_after"`
	DownRetryAfterMax    Duration `yaml:"down_retry_after_max"`
	RateLimitRetryAfter  Duration `yaml:"rate_limit_retry_after"`
}

type emergencyDoc struct {
	Fraction        float64  `yaml:"fraction"`
	SafetyChecks    int      `yaml:"safety_checks"`
	DefaultInterval Duration `yaml:"default_interval"`
}

type directDoc struct {
	RenewFraction   float64  `yaml:"renew_fraction"`
	ARIPollInterval Duration `yaml:"ari_poll_interval"`
	IssueTimeout    Duration `yaml:"issue_timeout"`
	RetryBackoff    Duration `yaml:"retry_backoff"`
	RetryBackoffMax Duration `yaml:"retry_backoff_max"`
	RSABits         int      `yaml:"rsa_bits"`
}

type dnsProxyDoc struct {
	PresentTimeout Duration `yaml:"present_timeout"`
	ChallengeTTL   Duration `yaml:"challenge_ttl"`
	MaxPerSource   limitDoc `yaml:"max_per_source"`
}

type upstreamDoc struct {
	HTTPTimeout       Duration `yaml:"http_timeout"`
	ValidationTimeout Duration `yaml:"validation_timeout"`
	IssueTimeout      Duration `yaml:"issue_timeout"`
	PollInterval      Duration `yaml:"poll_interval"`
	PrepareTimeout    Duration `yaml:"prepare_timeout"`
}

type resolverDoc struct {
	Timeout      Duration `yaml:"timeout"`
	MaxCNAMEHops int      `yaml:"max_cname_hops"`
}

type auditDoc struct {
	MaxFileBytes int64 `yaml:"max_file_bytes"`
	MaxFiles     int   `yaml:"max_files"`
}

func toLimitDoc(l core.Limit) limitDoc { return limitDoc{l.Count, Duration(l.Window)} }
func (l limitDoc) core() core.Limit    { return core.Limit{Count: l.Count, Window: l.Window.std()} }
func (d Duration) std() time.Duration  { return time.Duration(d) }

// docFromConfig maps the YAML-visible part of cfg to its document.
func docFromConfig(c *core.Config) *document {
	d := &document{
		Server: serverDoc{
			ExternalURL:   c.Server.ExternalURL,
			RealIPHeader:  c.Server.RealIPHeader,
			ReadTimeout:   Duration(c.Server.ReadTimeout),
			WriteTimeout:  Duration(c.Server.WriteTimeout),
			ShutdownGrace: Duration(c.Server.ShutdownGrace),
		},
		Zones: []zoneDoc{},
		Route53: route53Doc{
			Region:                c.Route53.Region,
			AccessKeyIDSecret:     c.Route53.AccessKeyIDSecret,
			SecretAccessKeySecret: c.Route53.SecretAccessKeySecret,
			TTL:                   Duration(c.Route53.TTL),
			ChangeTimeout:         Duration(c.Route53.ChangeTimeout),
			PropagationTimeout:    Duration(c.Route53.PropagationTimeout),
			PollInterval:          Duration(c.Route53.PollInterval),
		},
		Providers: []providerDoc{},
		LDAP: ldapDoc{
			URL: c.LDAP.URL, BindDN: c.LDAP.BindDN, BindPasswordSecret: c.LDAP.BindPasswordSecret,
			BaseDN: c.LDAP.BaseDN, UserFilter: c.LDAP.UserFilter, StartTLS: c.LDAP.StartTLS,
			InsecureSkipVerify: c.LDAP.InsecureSkipVerify, Timeout: Duration(c.LDAP.Timeout),
		},
		Sessions: sessionsDoc{TTL: Duration(c.Sessions.TTL), CookieName: c.Sessions.CookieName, CookieSecure: string(c.Sessions.CookieSecure)},
		Scheduler: schedulerDoc{
			AdmitWait: Duration(c.Scheduler.AdmitWait), FinalizeWait: Duration(c.Scheduler.FinalizeWait),
			OrderTTL: Duration(c.Scheduler.OrderTTL), BusyRetryAfter: Duration(c.Scheduler.BusyRetryAfter),
			ProcessingRetryAfter: Duration(c.Scheduler.ProcessingRetryAfter),
			DownRetryAfter:       Duration(c.Scheduler.DownRetryAfter), DownRetryAfterMax: Duration(c.Scheduler.DownRetryAfterMax),
			RateLimitRetryAfter: Duration(c.Scheduler.RateLimitRetryAfter),
		},
		Emergency: emergencyDoc{Fraction: c.Emergency.Fraction, SafetyChecks: c.Emergency.SafetyChecks, DefaultInterval: Duration(c.Emergency.DefaultInterval)},
		Direct: directDoc{
			RenewFraction: c.Direct.RenewFraction, ARIPollInterval: Duration(c.Direct.ARIPollInterval),
			IssueTimeout: Duration(c.Direct.IssueTimeout), RetryBackoff: Duration(c.Direct.RetryBackoff),
			RetryBackoffMax: Duration(c.Direct.RetryBackoffMax), RSABits: c.Direct.RSABits,
		},
		DNSProxy: dnsProxyDoc{
			PresentTimeout: Duration(c.DNSProxy.PresentTimeout), ChallengeTTL: Duration(c.DNSProxy.ChallengeTTL),
			MaxPerSource: toLimitDoc(c.DNSProxy.MaxPerSource),
		},
		Upstream: upstreamDoc{
			HTTPTimeout: Duration(c.Upstream.HTTPTimeout), ValidationTimeout: Duration(c.Upstream.ValidationTimeout),
			IssueTimeout: Duration(c.Upstream.IssueTimeout), PollInterval: Duration(c.Upstream.PollInterval),
			PrepareTimeout: Duration(c.Upstream.PrepareTimeout),
		},
		Resolver: resolverDoc{Timeout: Duration(c.Resolver.Timeout), MaxCNAMEHops: c.Resolver.MaxCNAMEHops},
		Audit:    auditDoc{MaxFileBytes: c.Audit.MaxFileBytes, MaxFiles: c.Audit.MaxFiles},
	}
	d.Server.TrustedProxies = []string{}
	for _, p := range c.Server.TrustedProxies {
		d.Server.TrustedProxies = append(d.Server.TrustedProxies, p.String())
	}
	for _, z := range c.Zones {
		d.Zones = append(d.Zones, zoneDoc{Name: z.Name, HostedZoneID: z.HostedZoneID, TrustedAccounts: slices.Clone(z.TrustedAccounts)})
	}
	for _, p := range c.Providers {
		l := p.Limits
		no, cd, cs := toLimitDoc(l.NewOrders), toLimitDoc(l.CertsPerDomain), toLimitDoc(l.CertsPerSet)
		d.Providers = append(d.Providers, providerDoc{
			Name: p.Name, Disabled: p.Disabled, DirectoryURL: p.DirectoryURL, Contact: p.Contact,
			EABKeyID: p.EABKeyID, EABSecret: p.EABSecretName, Profile: p.Profile,
			CAAIssuers: append([]string{}, p.CAAIssuers...), AccountURIHonoured: p.AccountURIHonoured,
			ARI: p.ARI, ARIExempt: p.ARIExempt,
			Limits: providerLimitsDoc{NewOrders: &no, CertsPerDomain: &cd, CertsPerSet: &cs,
				Concurrency: &l.Concurrency, RenewalReservePercent: &l.RenewalReservePercent},
		})
	}
	return d
}

// configFromDoc maps a decoded document to a core.Config carrying env and
// generation. Entries that cannot be converted (bad CIDR, bad zone name) are
// reported as problems; the result is only meaningful when there are none.
func configFromDoc(d *document, env Env, generation int) (*core.Config, Problems) {
	var c collector
	cfg := env.Apply(core.DefaultConfig())
	cfg.Generation = generation

	cfg.Server.ExternalURL = strings.TrimRight(strings.TrimSpace(d.Server.ExternalURL), "/")
	cfg.Server.RealIPHeader = strings.TrimSpace(d.Server.RealIPHeader)
	cfg.Server.ReadTimeout = d.Server.ReadTimeout.std()
	cfg.Server.WriteTimeout = d.Server.WriteTimeout.std()
	cfg.Server.ShutdownGrace = d.Server.ShutdownGrace.std()
	cfg.Server.TrustedProxies = nil
	for i, s := range d.Server.TrustedProxies {
		s = strings.TrimSpace(s)
		p, err := netip.ParsePrefix(s)
		if err != nil {
			a, aerr := netip.ParseAddr(s)
			if aerr != nil {
				c.errf(fmt.Sprintf("server.trusted_proxies[%d]", i), "%q is not a CIDR (10.0.0.0/8) or IP address", s)
				continue
			}
			p = netip.PrefixFrom(a, a.BitLen())
		}
		cfg.Server.TrustedProxies = append(cfg.Server.TrustedProxies, p.Masked())
	}

	cfg.Zones = nil
	for _, z := range d.Zones {
		name := strings.TrimSpace(z.Name)
		if n, err := names.Normalize(name); err == nil {
			name = n
		}
		var trusted []string
		for _, a := range z.TrustedAccounts {
			trusted = append(trusted, strings.TrimSpace(a))
		}
		cfg.Zones = append(cfg.Zones, core.ZoneConfig{Name: name, HostedZoneID: strings.TrimSpace(z.HostedZoneID), TrustedAccounts: trusted})
	}

	r := d.Route53
	cfg.Route53 = core.Route53Config{
		Region: strings.TrimSpace(r.Region), AccessKeyIDSecret: strings.TrimSpace(r.AccessKeyIDSecret),
		SecretAccessKeySecret: strings.TrimSpace(r.SecretAccessKeySecret), TTL: r.TTL.std(),
		ChangeTimeout: r.ChangeTimeout.std(), PropagationTimeout: r.PropagationTimeout.std(), PollInterval: r.PollInterval.std(),
	}

	cfg.Providers = nil
	for _, p := range d.Providers {
		lim := core.DefaultProviderLimits()
		if p.Limits.NewOrders != nil {
			lim.NewOrders = p.Limits.NewOrders.core()
		}
		if p.Limits.CertsPerDomain != nil {
			lim.CertsPerDomain = p.Limits.CertsPerDomain.core()
		}
		if p.Limits.CertsPerSet != nil {
			lim.CertsPerSet = p.Limits.CertsPerSet.core()
		}
		if p.Limits.Concurrency != nil {
			lim.Concurrency = *p.Limits.Concurrency
		}
		if p.Limits.RenewalReservePercent != nil {
			lim.RenewalReservePercent = *p.Limits.RenewalReservePercent
		}
		var issuers []string
		for _, s := range p.CAAIssuers {
			s = strings.ToLower(strings.TrimSpace(s))
			issuers = append(issuers, strings.TrimSuffix(s, "."))
		}
		cfg.Providers = append(cfg.Providers, core.ProviderConfig{
			Name: strings.TrimSpace(p.Name), Disabled: p.Disabled, DirectoryURL: strings.TrimSpace(p.DirectoryURL),
			Contact: strings.TrimSpace(p.Contact), EABKeyID: strings.TrimSpace(p.EABKeyID),
			EABSecretName: strings.TrimSpace(p.EABSecret), Profile: strings.TrimSpace(p.Profile),
			CAAIssuers: issuers, AccountURIHonoured: p.AccountURIHonoured, ARI: p.ARI, ARIExempt: p.ARIExempt,
			Limits: lim,
		})
	}

	l := d.LDAP
	cfg.LDAP = core.LDAPConfig{
		URL: strings.TrimSpace(l.URL), BindDN: strings.TrimSpace(l.BindDN),
		BindPasswordSecret: strings.TrimSpace(l.BindPasswordSecret), BaseDN: strings.TrimSpace(l.BaseDN),
		UserFilter: strings.TrimSpace(l.UserFilter), StartTLS: l.StartTLS, InsecureSkipVerify: l.InsecureSkipVerify,
		Timeout: l.Timeout.std(),
	}
	cfg.Sessions = core.SessionConfig{TTL: d.Sessions.TTL.std(), CookieName: strings.TrimSpace(d.Sessions.CookieName), CookieSecure: cookieSecureMode(d.Sessions.CookieSecure)}
	s := d.Scheduler
	cfg.Scheduler = core.SchedulerConfig{
		AdmitWait: s.AdmitWait.std(), FinalizeWait: s.FinalizeWait.std(), OrderTTL: s.OrderTTL.std(),
		BusyRetryAfter: s.BusyRetryAfter.std(), ProcessingRetryAfter: s.ProcessingRetryAfter.std(),
		DownRetryAfter: s.DownRetryAfter.std(), DownRetryAfterMax: s.DownRetryAfterMax.std(),
		RateLimitRetryAfter: s.RateLimitRetryAfter.std(),
	}
	cfg.Emergency = core.EmergencyConfig{Fraction: d.Emergency.Fraction, SafetyChecks: d.Emergency.SafetyChecks, DefaultInterval: d.Emergency.DefaultInterval.std()}
	cfg.Direct = core.DirectConfig{
		RenewFraction: d.Direct.RenewFraction, ARIPollInterval: d.Direct.ARIPollInterval.std(),
		IssueTimeout: d.Direct.IssueTimeout.std(), RetryBackoff: d.Direct.RetryBackoff.std(),
		RetryBackoffMax: d.Direct.RetryBackoffMax.std(), RSABits: d.Direct.RSABits,
	}
	cfg.DNSProxy = core.DNSProxyConfig{PresentTimeout: d.DNSProxy.PresentTimeout.std(), ChallengeTTL: d.DNSProxy.ChallengeTTL.std(), MaxPerSource: d.DNSProxy.MaxPerSource.core()}
	u := d.Upstream
	cfg.Upstream = core.UpstreamConfig{
		HTTPTimeout: u.HTTPTimeout.std(), ValidationTimeout: u.ValidationTimeout.std(), IssueTimeout: u.IssueTimeout.std(),
		PollInterval: u.PollInterval.std(), PrepareTimeout: u.PrepareTimeout.std(),
	}
	cfg.Resolver = core.ResolverConfig{Timeout: d.Resolver.Timeout.std(), MaxCNAMEHops: d.Resolver.MaxCNAMEHops}
	cfg.Audit = core.AuditConfig{MaxFileBytes: d.Audit.MaxFileBytes, MaxFiles: d.Audit.MaxFiles}
	return cfg, c.problems
}

// cookieSecureMode reads sessions.cookie_secure: the three modes, or the
// booleans earlier generations used. Anything else is passed through for the
// validator to reject.
func cookieSecureMode(s string) core.CookieSecureMode {
	switch v := strings.ToLower(strings.TrimSpace(s)); v {
	case "", "auto":
		return core.CookieSecureAuto
	case "true", "always":
		return core.CookieSecureAlways
	case "false", "never":
		return core.CookieSecureNever
	default:
		return core.CookieSecureMode(v)
	}
}

var yamlLineRe = regexp.MustCompile(`^line (\d+): (.*)$`)

// decode strictly decodes data over the defaults. Unknown fields, wrong types,
// duplicate keys and multiple documents are problems.
func decode(data []byte) (*document, Problems) {
	doc := docFromConfig(core.DefaultConfig())
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	if err := dec.Decode(doc); err != nil && !errors.Is(err, io.EOF) {
		return nil, yamlProblems(err)
	}
	var extra yaml.Node
	if err := dec.Decode(&extra); err == nil {
		return nil, Problems{{Message: "YAML contains more than one document"}}
	} else if !errors.Is(err, io.EOF) {
		return nil, yamlProblems(err)
	}
	return doc, nil
}

// yamlProblems turns a yaml.v3 error into one problem per finding. The path
// is "line N" because the library reports positions, not field paths.
func yamlProblems(err error) Problems {
	var te *yaml.TypeError
	var msgs []string
	if errors.As(err, &te) {
		msgs = te.Errors
	} else {
		msgs = []string{strings.TrimPrefix(err.Error(), "yaml: ")}
	}
	var out Problems
	for _, m := range msgs {
		m = strings.TrimPrefix(m, "yaml: ")
		if sm := yamlLineRe.FindStringSubmatch(m); sm != nil {
			out = append(out, Problem{Path: "line " + sm[1], Message: sm[2]})
			continue
		}
		if i := strings.Index(m, "line "); i == 0 {
			if j := strings.Index(m, ": "); j > 0 {
				out = append(out, Problem{Path: m[:j], Message: m[j+2:]})
				continue
			}
		}
		out = append(out, Problem{Message: m})
	}
	return out
}

// Report is the outcome of parsing and validating a configuration.
type Report struct {
	// Errors prevent activation.
	Errors Problems
	// Warnings do not.
	Warnings Problems
}

// OK reports whether there are no errors.
func (r Report) OK() bool { return len(r.Errors) == 0 }

// Parse decodes data strictly (unknown fields are errors), starts from the
// defaults for everything omitted, merges env and generation into the result
// and validates it semantically. The *core.Config is non-nil only when
// Report.OK. Secret existence is not checked here (see CheckSecrets).
func Parse(data []byte, env Env, generation int) (*core.Config, Report) {
	cfg, rep := parse(data, env, generation)
	if !rep.OK() {
		return nil, rep
	}
	return cfg, rep
}

// parse is Parse but returns the configuration whenever decoding succeeded,
// even when validation found errors, so callers can run further checks and
// report everything together. It is nil only for syntax-level failures.
func parse(data []byte, env Env, generation int) (*core.Config, Report) {
	doc, probs := decode(data)
	if len(probs) > 0 {
		return nil, Report{Errors: probs}
	}
	cfg, probs := configFromDoc(doc, env, generation)
	rep := Validate(cfg)
	rep.Errors = append(probs, rep.Errors...)
	return cfg, rep
}

// Marshal renders the YAML-visible part of cfg as YAML (without comments).
// Parse(Marshal(cfg)) yields the same configuration, modulo env fields.
func Marshal(cfg *core.Config) ([]byte, error) {
	var buf bytes.Buffer
	enc := yaml.NewEncoder(&buf)
	enc.SetIndent(2)
	if err := enc.Encode(docFromConfig(cfg)); err != nil {
		return nil, err
	}
	if err := enc.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// DefaultYAML is the content of generation 000001: the defaults, with a
// header comment.
func DefaultYAML() []byte {
	body, err := Marshal(core.DefaultConfig())
	if err != nil {
		panic(err) // the default configuration always marshals
	}
	head := "# TLS broker configuration (generation 000001: defaults).\n" +
		"# Edit it in the web UI; every save creates a new generation.\n" +
		"# Secret values never go here, only secret names.\n"
	return append([]byte(head), body...)
}
