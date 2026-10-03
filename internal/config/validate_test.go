package config

import (
	"fmt"
	"net/netip"
	"strings"
	"testing"
	"time"

	"tls-broker/internal/core"
)

func TestFixtureIsValid(t *testing.T) {
	rep := Validate(testConfig())
	if !rep.OK() {
		t.Fatal(rep.Errors)
	}
	if rep := Validate(testEnv().Apply(core.DefaultConfig())); !rep.OK() {
		t.Fatalf("defaults invalid: %v", rep.Errors)
	}
}

// Every rule: a mutation of the valid fixture and the path it must be
// reported under.
func TestValidationRules(t *testing.T) {
	type mut func(c *core.Config)
	cases := []struct {
		name string
		path string
		m    mut
	}{
		{"external url missing", "server.external_url", func(c *core.Config) { c.Server.ExternalURL = "" }},
		{"external url scheme", "server.external_url", func(c *core.Config) { c.Server.ExternalURL = "ftp://x.example" }},
		{"external url query", "server.external_url", func(c *core.Config) { c.Server.ExternalURL = "https://x.example/?a=b" }},
		{"proxies need header", "server.real_ip_header", func(c *core.Config) { c.Server.RealIPHeader = "" }},
		{"bad header", "server.real_ip_header", func(c *core.Config) { c.Server.RealIPHeader = "X Real IP" }},
		{"xff refused", "server.real_ip_header", func(c *core.Config) { c.Server.RealIPHeader = "x-forwarded-for" }},
		{"trust everyone", "server.trusted_proxies[0]", func(c *core.Config) { c.Server.TrustedProxies = []netip.Prefix{mustPrefix("0.0.0.0/0")} }},
		{"read timeout low", "server.read_timeout", func(c *core.Config) { c.Server.ReadTimeout = 0 }},
		{"write below read", "server.write_timeout", func(c *core.Config) { c.Server.ReadTimeout = 10 * time.Minute; c.Server.WriteTimeout = 9 * time.Minute }},
		{"write below held request", "server.write_timeout", func(c *core.Config) { c.Server.WriteTimeout = 3 * time.Minute }},
		{"shutdown grace", "server.shutdown_grace", func(c *core.Config) { c.Server.ShutdownGrace = time.Hour }},

		{"zone bad name", "zones[0].name", func(c *core.Config) { c.Zones[0].Name = "not a zone" }},
		{"zone single label", "zones[0].name", func(c *core.Config) { c.Zones[0].Name = "com" }},
		{"zone wildcard", "zones[0].name", func(c *core.Config) { c.Zones[0].Name = "*.example.com" }},
		{"zone not normalized", "zones[0].name", func(c *core.Config) { c.Zones[0].Name = "Example.com" }},
		{"zone duplicate", "zones[1].name", func(c *core.Config) { c.Zones[1].Name = "example.com" }},
		{"zone bad id", "zones[0].hosted_zone_id", func(c *core.Config) { c.Zones[0].HostedZoneID = "/hostedzone/Z123" }},
		{"zone lower-case id", "zones[0].hosted_zone_id", func(c *core.Config) { c.Zones[0].HostedZoneID = "z123abc" }},
		{"trusted account empty", "zones[0].trusted_accounts[0]", trusted("")},
		{"trusted account http", "zones[0].trusted_accounts[0]", trusted("http://primary.test/acme/acct/1")},
		{"trusted account relative", "zones[0].trusted_accounts[0]", trusted("/acme/acct/1")},
		{"trusted account no host", "zones[0].trusted_accounts[0]", trusted("https:///acme/acct/1")},
		{"trusted account query", "zones[0].trusted_accounts[0]", trusted("https://primary.test/acme/acct/1?x=1")},
		{"trusted account fragment", "zones[0].trusted_accounts[0]", trusted("https://primary.test/acme/acct/1#a")},
		{"trusted account user info", "zones[0].trusted_accounts[0]", trusted("https://u@primary.test/acme/acct/1")},
		{"trusted account semicolon", "zones[0].trusted_accounts[0]", trusted("https://primary.test/acme/acct/1;x")},
		{"trusted account non-ASCII", "zones[0].trusted_accounts[0]", trusted("https://primary.test/acme/acct/\u00e4")},
		{"trusted account duplicate", "zones[0].trusted_accounts[1]", trusted("https://primary.test/acme/acct/1", "https://primary.test/acme/acct/1")},
		{"trusted accounts too many", "zones[0].trusted_accounts", func(c *core.Config) {
			for i := range MaxTrustedAccounts + 1 {
				c.Zones[0].TrustedAccounts = append(c.Zones[0].TrustedAccounts, fmt.Sprintf("https://primary.test/acme/acct/%d", i))
			}
		}},

		{"region", "route53.region", func(c *core.Config) { c.Route53.Region = "mars" }},
		{"route53 half credentials", "route53.access_key_id_secret", func(c *core.Config) { c.Route53.SecretAccessKeySecret = "" }},
		{"route53 secret name", "route53.secret_access_key_secret", func(c *core.Config) { c.Route53.SecretAccessKeySecret = "../etc/passwd" }},
		{"route53 reserved secret", "route53.access_key_id_secret", func(c *core.Config) { c.Route53.AccessKeyIDSecret = "provider-account-key.primary" }},
		{"route53 ttl", "route53.ttl", func(c *core.Config) { c.Route53.TTL = 1500 * time.Millisecond }},
		{"route53 ttl zero", "route53.ttl", func(c *core.Config) { c.Route53.TTL = 0 }},
		{"route53 change timeout", "route53.change_timeout", func(c *core.Config) { c.Route53.ChangeTimeout = 0 }},
		{"route53 poll vs propagation", "route53.poll_interval", func(c *core.Config) { c.Route53.PollInterval = 3 * time.Minute }},

		{"provider name empty", "providers[0].name", func(c *core.Config) { c.Providers[0].Name = "" }},
		{"provider name chars", "providers[0].name", func(c *core.Config) { c.Providers[0].Name = "Lets Encrypt" }},
		{"provider duplicate", "providers[1].name", func(c *core.Config) { c.Providers[1].Name = "primary" }},
		{"provider url http", "providers[0].directory_url", func(c *core.Config) { c.Providers[0].DirectoryURL = "http://acme.example/dir" }},
		{"provider url empty", "providers[0].directory_url", func(c *core.Config) { c.Providers[0].DirectoryURL = "" }},
		{"provider contact", "providers[0].contact", func(c *core.Config) { c.Providers[0].Contact = "not an address" }},
		{"provider eab half", "providers[0].eab_key_id", func(c *core.Config) { c.Providers[0].EABKeyID = "kid" }},
		{"provider eab secret name", "providers[1].eab_secret", func(c *core.Config) { c.Providers[1].EABSecretName = "Bad/Name" }},
		{"provider profile", "providers[0].profile", func(c *core.Config) { c.Providers[0].Profile = "two words" }},
		{"provider caa missing", "providers[0].caa_issuers", func(c *core.Config) { c.Providers[0].CAAIssuers = nil }},
		{"provider caa bad", "providers[0].caa_issuers[0]", func(c *core.Config) { c.Providers[0].CAAIssuers = []string{"bad issuer"} }},
		{"provider ari exempt", "providers[1].ari_exempt", func(c *core.Config) { c.Providers[1].ARI = false; c.Providers[1].ARIExempt = true }},
		{"limit count negative", "providers[0].limits.new_orders.count", func(c *core.Config) { c.Providers[0].Limits.NewOrders.Count = -1 }},
		{"limit window", "providers[0].limits.certs_per_set.window", func(c *core.Config) { c.Providers[0].Limits.CertsPerSet.Window = 0 }},
		{"limit concurrency", "providers[0].limits.concurrency", func(c *core.Config) { c.Providers[0].Limits.Concurrency = 0 }},
		{"limit reserve", "providers[0].limits.renewal_reserve_percent", func(c *core.Config) { c.Providers[0].Limits.RenewalReservePercent = 95 }},
		{"all providers disabled", "providers", func(c *core.Config) { c.Providers[0].Disabled = true; c.Providers[1].Disabled = true }},

		{"ldap url scheme", "ldap.url", func(c *core.Config) { c.LDAP.URL = "http://ldap.example.com" }},
		{"ldap url path", "ldap.url", func(c *core.Config) { c.LDAP.URL = "ldaps://h:636/dc=x" }},
		{"ldap no host", "ldap.url", func(c *core.Config) { c.LDAP.URL = "ldaps://" }},
		{"ldap starttls on ldaps", "ldap.starttls", func(c *core.Config) { c.LDAP.StartTLS = true }},
		{"ldap settings without url", "ldap.url", func(c *core.Config) { c.LDAP.URL = "" }},
		{"ldap bind half", "ldap.bind_dn", func(c *core.Config) { c.LDAP.BindPasswordSecret = "" }},
		{"ldap bind dn", "ldap.bind_dn", func(c *core.Config) { c.LDAP.BindDN = "not a dn" }},
		{"ldap secret name", "ldap.bind_password_secret", func(c *core.Config) { c.LDAP.BindPasswordSecret = "UPPER" }},
		{"ldap base dn missing", "ldap.base_dn", func(c *core.Config) { c.LDAP.BaseDN = "" }},
		{"ldap base dn bad", "ldap.base_dn", func(c *core.Config) { c.LDAP.BaseDN = "nonsense" }},
		{"ldap filter missing", "ldap.user_filter", func(c *core.Config) { c.LDAP.UserFilter = "" }},
		{"ldap filter placeholder", "ldap.user_filter", func(c *core.Config) { c.LDAP.UserFilter = "(uid=bob)" }},
		{"ldap filter twice", "ldap.user_filter", func(c *core.Config) { c.LDAP.UserFilter = "(|(uid=%s)(mail=%s))" }},
		{"ldap filter syntax", "ldap.user_filter", func(c *core.Config) { c.LDAP.UserFilter = "(uid=%s" }},
		{"ldap timeout", "ldap.timeout", func(c *core.Config) { c.LDAP.Timeout = 0 }},

		{"session ttl", "sessions.ttl", func(c *core.Config) { c.Sessions.TTL = time.Minute }},
		{"cookie name", "sessions.cookie_name", func(c *core.Config) { c.Sessions.CookieName = "a b;c" }},

		{"admit wait", "scheduler.admit_wait", func(c *core.Config) { c.Scheduler.AdmitWait = 0 }},
		{"order ttl", "scheduler.order_ttl", func(c *core.Config) { c.Scheduler.OrderTTL = 48 * time.Hour }},
		{"down retry order", "scheduler.down_retry_after", func(c *core.Config) { c.Scheduler.DownRetryAfter = time.Hour }},

		{"emergency fraction", "emergency.fraction", func(c *core.Config) { c.Emergency.Fraction = 0.9 }},
		{"emergency fraction zero", "emergency.fraction", func(c *core.Config) { c.Emergency.Fraction = 0 }},
		{"emergency checks", "emergency.safety_checks", func(c *core.Config) { c.Emergency.SafetyChecks = 0 }},
		{"emergency interval", "emergency.default_interval", func(c *core.Config) { c.Emergency.DefaultInterval = time.Minute }},

		{"direct fraction", "direct.renew_fraction", func(c *core.Config) { c.Direct.RenewFraction = 1 }},
		{"direct rsa", "direct.rsa_bits", func(c *core.Config) { c.Direct.RSABits = 1024 }},
		{"direct backoff", "direct.retry_backoff", func(c *core.Config) { c.Direct.RetryBackoff = 2 * time.Hour }},
		{"direct ari poll", "direct.ari_poll_interval", func(c *core.Config) { c.Direct.ARIPollInterval = 0 }},

		{"dns present", "dns_proxy.present_timeout", func(c *core.Config) { c.DNSProxy.PresentTimeout = 0 }},
		{"dns challenge ttl", "dns_proxy.challenge_ttl", func(c *core.Config) { c.DNSProxy.ChallengeTTL = time.Minute }},
		{"dns per source", "dns_proxy.max_per_source.window", func(c *core.Config) { c.DNSProxy.MaxPerSource.Window = 0 }},

		{"upstream http", "upstream.http_timeout", func(c *core.Config) { c.Upstream.HTTPTimeout = 0 }},
		{"upstream prepare", "upstream.prepare_timeout", func(c *core.Config) { c.Upstream.PrepareTimeout = time.Minute }},
		{"resolver timeout", "resolver.timeout", func(c *core.Config) { c.Resolver.Timeout = 0 }},
		{"resolver hops", "resolver.max_cname_hops", func(c *core.Config) { c.Resolver.MaxCNAMEHops = 0 }},
		{"audit size", "audit.max_file_bytes", func(c *core.Config) { c.Audit.MaxFileBytes = 10 }},
		{"audit files", "audit.max_files", func(c *core.Config) { c.Audit.MaxFiles = -1 }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := testConfig()
			tc.m(c)
			rep := Validate(c)
			for _, p := range rep.Errors {
				if p.Path == tc.path {
					return
				}
			}
			t.Fatalf("no error at %q; got %v", tc.path, rep.Errors)
		})
	}
}

func trusted(accounts ...string) func(c *core.Config) {
	return func(c *core.Config) { c.Zones[0].TrustedAccounts = accounts }
}

// Trusted accounts at a provider's directory host are valid without a
// warning; one at a host no enabled provider uses is probably mistyped.
func TestTrustedAccountHosts(t *testing.T) {
	c := testConfig()
	c.Zones[0].TrustedAccounts = []string{"https://primary.test/acme/acct/1", "https://FALLBACK.test/acme/acct/2"}
	c.Zones[1].TrustedAccounts = []string{"https://ca.elsewhere.test/acct/3"}
	rep := Validate(c)
	if !rep.OK() {
		t.Fatal(rep.Errors)
	}
	if len(rep.Warnings) != 1 || rep.Warnings[0].Path != "zones[1].trusted_accounts[0]" {
		t.Fatalf("warnings %v", rep.Warnings)
	}
}

func TestValidationReportsEverythingAtOnce(t *testing.T) {
	c := testConfig()
	c.Zones[0].Name = "bad name"
	c.Providers[0].DirectoryURL = "http://x"
	c.LDAP.UserFilter = "(uid=x)"
	c.Direct.RSABits = 1
	rep := Validate(c)
	if len(rep.Errors) < 4 {
		t.Fatalf("want >= 4 errors, got %v", rep.Errors)
	}
	for _, p := range rep.Errors {
		if p.Path == "" || p.Message == "" {
			t.Fatalf("problem lacks path or message: %+v", p)
		}
	}
}

func TestLDAPDisabledNeedsNothing(t *testing.T) {
	c := testConfig()
	c.LDAP = core.LDAPConfig{Timeout: 10 * time.Second}
	if rep := Validate(c); !rep.OK() {
		t.Fatal(rep.Errors)
	}
	if len(ValidateLDAP(c.LDAP)) != 0 {
		t.Fatal("unconfigured LDAP is valid")
	}
}

// An omitted hosted_zone_id is valid (the engine discovers it by name) and
// does not take part in the duplicate-ID warning.
func TestHostedZoneIDOptional(t *testing.T) {
	c := testConfig()
	c.Zones[0].HostedZoneID = ""
	c.Zones = append(c.Zones, core.ZoneConfig{Name: "example.net"})
	rep := Validate(c)
	if !rep.OK() {
		t.Fatal(rep.Errors)
	}
	for _, w := range rep.Warnings {
		if strings.Contains(w.Path, "hosted_zone_id") {
			t.Fatalf("unexpected warning %v", w)
		}
	}
}

func TestWarnings(t *testing.T) {
	c := testConfig()
	c.Server.ExternalURL = "http://broker.test"
	c.LDAP.InsecureSkipVerify = true
	c.Sessions.CookieSecure = core.CookieSecureAlways // while external_url is http
	c.Zones = append(c.Zones, core.ZoneConfig{Name: "example.net", HostedZoneID: c.Zones[0].HostedZoneID})
	rep := Validate(c)
	if !rep.OK() {
		t.Fatal(rep.Errors)
	}
	got := strings.Join(rep.Warnings.Strings(), "\n")
	for _, p := range []string{"server.external_url", "ldap.insecure_skip_verify", "sessions.cookie_secure", "zones[2].hosted_zone_id"} {
		if !strings.Contains(got, p) {
			t.Errorf("missing warning %s in:\n%s", p, got)
		}
	}
}

func TestCheckSecrets(t *testing.T) {
	c := testConfig()
	probs := CheckSecrets(c, []string{"route53-access-key-id", "ldap-bind-password"})
	got := strings.Join(probs.Strings(), "\n")
	for _, p := range []string{"route53.secret_access_key_secret", "providers[1].eab_secret"} {
		if !strings.Contains(got, p) {
			t.Errorf("missing %s in:\n%s", p, got)
		}
	}
	if len(probs) != 2 {
		t.Fatal(probs)
	}
	if len(CheckSecrets(c, []string{"route53-access-key-id", "route53-secret-access-key", "eab.fallback", "ldap-bind-password"})) != 0 {
		t.Fatal("all present")
	}
}

func TestValidSecretName(t *testing.T) {
	for _, n := range []string{"a", "route53-key", "eab.fallback", "provider-account-key.le", "a_b-c.9"} {
		if !ValidSecretName(n) {
			t.Errorf("%q rejected", n)
		}
	}
	for _, n := range []string{"", ".hidden", "-a", "A", "a/b", "../a", "a b", "a\x00", strings.Repeat("a", 129)} {
		if ValidSecretName(n) {
			t.Errorf("%q accepted", n)
		}
	}
}

func mustPrefix(s string) netip.Prefix { return netip.MustParsePrefix(s) }
