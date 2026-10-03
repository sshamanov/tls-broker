package config

import (
	"net/netip"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	"tls-broker/internal/core"
	"tls-broker/internal/core/coretest"
)

// testEnv is the environment used by every test; DataDir is a fixed fake
// because Parse does not touch the file system.
func testEnv() Env {
	e := DefaultEnv()
	e.DataDir = "/data"
	e.Bootstrap.Admins = []string{"alice"}
	return e
}

// testConfig is a valid configuration with every optional section filled in.
func testConfig() *core.Config {
	c := coretest.NewConfig()
	testEnv().Apply(c)
	c.Route53.AccessKeyIDSecret = "route53-access-key-id"
	c.Route53.SecretAccessKeySecret = "route53-secret-access-key"
	c.Providers[1].EABKeyID = "kid-1"
	c.Providers[1].EABSecretName = "eab.fallback"
	c.Providers[1].Profile = "classic"
	c.Providers[1].Contact = "ops@example.com"
	c.LDAP = core.LDAPConfig{
		URL: "ldaps://ldap.example.com:636", BindDN: "cn=svc,dc=example,dc=com", BindPasswordSecret: "ldap-bind-password",
		BaseDN: "ou=people,dc=example,dc=com", UserFilter: "(&(objectClass=person)(uid=%s))", Timeout: 10 * time.Second,
	}
	return c
}

func TestRoundTrip(t *testing.T) {
	for name, want := range map[string]*core.Config{"fixture": testConfig(), "defaults": testEnv().Apply(core.DefaultConfig())} {
		t.Run(name, func(t *testing.T) {
			want.Generation = 7
			data, err := Marshal(want)
			if err != nil {
				t.Fatal(err)
			}
			got, rep := Parse(data, testEnv(), 7)
			if !rep.OK() {
				t.Fatalf("%v\n%s", rep.Errors, data)
			}
			if !reflect.DeepEqual(got, want) {
				t.Fatalf("round trip differs\n got %+v\nwant %+v\n%s", got, want, data)
			}
			again, _ := Marshal(got)
			if string(again) != string(data) {
				t.Fatalf("marshal not stable:\n%s\n---\n%s", data, again)
			}
		})
	}
}

func TestEmptyYAMLMeansDefaults(t *testing.T) {
	for _, in := range []string{"", "# only a comment\n", "{}\n"} {
		cfg, rep := Parse([]byte(in), testEnv(), 1)
		if !rep.OK() {
			t.Fatalf("%q: %v", in, rep.Errors)
		}
		want := testEnv().Apply(core.DefaultConfig())
		if !reflect.DeepEqual(cfg, want) {
			t.Fatalf("%q: not defaults: %+v", in, cfg)
		}
	}
}

func TestPartialYAMLKeepsOtherDefaults(t *testing.T) {
	cfg, rep := Parse([]byte("scheduler:\n  admit_wait: 45s\nproviders:\n  - name: le\n    directory_url: https://acme.example/dir\n    caa_issuers: [letsencrypt.org]\n    limits:\n      concurrency: 2\n"), testEnv(), 3)
	if !rep.OK() {
		t.Fatal(rep.Errors)
	}
	if cfg.Generation != 3 || cfg.Scheduler.AdmitWait != 45*time.Second || cfg.Scheduler.FinalizeWait != 20*time.Second {
		t.Fatalf("scheduler: %+v", cfg.Scheduler)
	}
	lim := cfg.Providers[0].Limits
	def := core.DefaultProviderLimits()
	if lim.Concurrency != 2 || lim.NewOrders != def.NewOrders || lim.RenewalReservePercent != def.RenewalReservePercent {
		t.Fatalf("limits: %+v", lim)
	}
	if cfg.DataDir != "/data" || cfg.Bootstrap.Admins[0] != "alice" {
		t.Fatalf("env not merged: %+v", cfg)
	}
}

func TestStrictDecoding(t *testing.T) {
	cases := map[string]struct{ yaml, path string }{
		"unknown top level":     {"bogus: 1\n", "line 1"},
		"unknown nested":        {"server:\n  listne: x\n", "line 2"},
		"env-only listen":       {"server:\n  listen: 127.0.0.1:1\n", "line 2"},
		"env-only admins":       {"bootstrap:\n  admins: [a]\n", "line 1"},
		"unknown in provider":   {"providers:\n  - name: a\n    secret: x\n", "line 3"},
		"wrong type":            {"direct:\n  rsa_bits: lots\n", "line 2"},
		"duration without unit": {"scheduler:\n  admit_wait: 30\n", "line 2"},
		"bad duration":          {"scheduler:\n  admit_wait: soon\n", "line 2"},
		"two documents":         {"zones: []\n---\nzones: []\n", ""},
		"not yaml":              {"a: [\n", ""},
		"duplicate key":         {"server: {}\nserver: {}\n", ""},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			cfg, rep := Parse([]byte(tc.yaml), testEnv(), 1)
			if cfg != nil || rep.OK() {
				t.Fatal("accepted")
			}
			if tc.path != "" && rep.Errors[0].Path != tc.path {
				t.Fatalf("path %q, want %q (%v)", rep.Errors[0].Path, tc.path, rep.Errors)
			}
		})
	}
}

func TestDuration(t *testing.T) {
	for in, want := range map[string]time.Duration{
		"90s": 90 * time.Second, "5m": 5 * time.Minute, "1h30m": 90 * time.Minute, "7d": 7 * 24 * time.Hour,
		"1d12h": 36 * time.Hour, "250ms": 250 * time.Millisecond, "0": 0,
	} {
		d, err := ParseDuration(in)
		if err != nil || d != want {
			t.Errorf("%q: %v %v", in, d, err)
		}
		if back, err := ParseDuration(FormatDuration(want)); err != nil || back != want {
			t.Errorf("format %q: %v %v", FormatDuration(want), back, err)
		}
	}
	for _, in := range []string{"", "5", "d", "1x", "-", "1.5d"} {
		if _, err := ParseDuration(in); err == nil {
			t.Errorf("%q accepted", in)
		}
	}
	for d, want := range map[time.Duration]string{36 * time.Hour: "1d12h", 2 * time.Minute: "2m", 90 * time.Second: "1m30s", 7 * 24 * time.Hour: "7d"} {
		if got := FormatDuration(d); got != want {
			t.Errorf("%v: %q want %q", d, got, want)
		}
	}
}

func TestNormalization(t *testing.T) {
	cfg, rep := Parse([]byte("server:\n  external_url: https://b.example.com/\n  trusted_proxies: [10.1.2.3/8, 192.168.0.9, \"::1\"]\nzones:\n  - {name: Example.COM., hosted_zone_id: Z1}\nproviders:\n  - name: le\n    directory_url: https://x.example/dir\n    caa_issuers: [LetsEncrypt.org.]\n"), testEnv(), 1)
	if !rep.OK() {
		t.Fatal(rep.Errors)
	}
	if cfg.Server.ExternalURL != "https://b.example.com" || cfg.Zones[0].Name != "example.com" || cfg.Providers[0].CAAIssuers[0] != "letsencrypt.org" {
		t.Fatalf("%+v", cfg)
	}
	want := []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8"), netip.MustParsePrefix("192.168.0.9/32"), netip.MustParsePrefix("::1/128")}
	if !reflect.DeepEqual(cfg.Server.TrustedProxies, want) {
		t.Fatalf("%v", cfg.Server.TrustedProxies)
	}
}

func TestBadProxyAndZoneReportedWithPath(t *testing.T) {
	_, rep := Parse([]byte("server:\n  trusted_proxies: [nonsense, 10.0.0.0/8]\nzones:\n  - {name: \"-bad-.com\", hosted_zone_id: Z1}\n"), testEnv(), 1)
	got := strings.Join(rep.Errors.Strings(), "\n")
	for _, p := range []string{"server.trusted_proxies[0]", "zones[0].name"} {
		if !strings.Contains(got, p) {
			t.Errorf("missing %s in:\n%s", p, got)
		}
	}
}

// TestDocExampleParses keeps docs/configuration.md honest: the complete
// example must parse and validate, and the documented values must come out.
func TestDocExampleParses(t *testing.T) {
	doc, err := os.ReadFile("../../docs/configuration.md")
	if err != nil {
		t.Fatal(err)
	}
	s := string(doc)
	i := strings.Index(s, "<!-- example:begin -->")
	j := strings.Index(s, "<!-- example:end -->")
	if i < 0 || j < i {
		t.Fatal("example markers missing")
	}
	block := s[i:j]
	block = block[strings.Index(block, "```yaml\n")+len("```yaml\n"):]
	block = block[:strings.Index(block, "```")]
	cfg, rep := Parse([]byte(block), testEnv(), 1)
	if !rep.OK() {
		t.Fatal(rep.Errors)
	}
	if len(deprecations(mustDecode(t, block))) != 0 {
		t.Fatal("the example uses a removed key")
	}
	if len(cfg.Zones) != 2 || len(cfg.Providers) != 2 || cfg.Providers[0].Name != "letsencrypt" ||
		cfg.Providers[1].EABSecretName != "eab.google" || cfg.LDAP.URL == "" || cfg.Sessions.TTL != 30*24*time.Hour {
		t.Fatalf("%+v", cfg)
	}
	if rep := CheckSecrets(cfg, []string{"route53-access-key-id", "route53-secret-access-key", "eab.google", "ldap-bind-password"}); len(rep) != 0 {
		t.Fatal(rep)
	}
}

// sessions.cookie_secure defaults to auto (Secure when the login came over
// HTTPS), accepts the three modes, still reads the booleans of earlier
// generations, and rejects anything else with a path.
func TestCookieSecureModes(t *testing.T) {
	cases := map[string]core.CookieSecureMode{
		"": core.CookieSecureAuto, "auto": core.CookieSecureAuto, "Always": core.CookieSecureAlways,
		"never": core.CookieSecureNever, "true": core.CookieSecureAlways, "false": core.CookieSecureNever,
	}
	for in, want := range cases {
		yaml := ""
		if in != "" {
			yaml = "sessions:\n  cookie_secure: " + in + "\n"
		}
		cfg, rep := Parse([]byte(yaml), testEnv(), 1)
		if !rep.OK() {
			t.Fatalf("%q: %v", in, rep.Errors)
		}
		if cfg.Sessions.CookieSecure != want {
			t.Errorf("%q: mode %q, want %q", in, cfg.Sessions.CookieSecure, want)
		}
	}
	_, rep := Parse([]byte("sessions:\n  cookie_secure: sometimes\n"), testEnv(), 1)
	if rep.OK() || !strings.Contains(strings.Join(rep.Errors.Strings(), "\n"), "sessions.cookie_secure") {
		t.Fatalf("bad mode accepted: %+v", rep)
	}
	// A generation written by this version round-trips as the mode word.
	out, err := Marshal(testEnv().Apply(core.DefaultConfig()))
	if err != nil || !strings.Contains(string(out), "cookie_secure: auto") {
		t.Fatalf("rendered default:\n%s", out)
	}
}

// zones[].trusted_accounts was removed; older generations that still have
// it parse, in any shape, with one deprecation warning per zone and no
// effect on the configuration.
func TestDeprecatedTrustedAccounts(t *testing.T) {
	plain, rep := Parse([]byte("zones:\n  - name: example.com\n  - name: example.org\n"), testEnv(), 1)
	if !rep.OK() {
		t.Fatal(rep.Errors)
	}
	for name, yaml := range map[string]string{
		"list":   "    trusted_accounts:\n      - https://acme-v02.api.letsencrypt.org/acme/acct/111111111\n      - https://acme-v02.api.letsencrypt.org/acme/acct/222222222\n",
		"empty":  "    trusted_accounts: []\n",
		"scalar": "    trusted_accounts: not-a-list\n",
		"bad":    "    trusted_accounts:\n      - http://x y\n",
	} {
		t.Run(name, func(t *testing.T) {
			in := "zones:\n  - name: example.com\n  - name: example.org\n" + yaml
			cfg, rep := Parse([]byte(in), testEnv(), 1)
			if !rep.OK() {
				t.Fatal(rep.Errors)
			}
			if !reflect.DeepEqual(cfg.Zones, plain.Zones) {
				t.Fatalf("zones %+v, want %+v", cfg.Zones, plain.Zones)
			}
			var dep []Problem
			for _, w := range rep.Warnings {
				if strings.Contains(w.Path, "trusted_accounts") {
					dep = append(dep, w)
				}
			}
			if len(dep) != 1 || dep[0].Path != "zones[1].trusted_accounts" || !strings.Contains(dep[0].Message, "ignored") {
				t.Fatalf("warnings %v", rep.Warnings)
			}
			if out, _ := Marshal(cfg); strings.Contains(string(out), "trusted_accounts") {
				t.Fatalf("rendered:\n%s", out)
			}
		})
	}
	// The key is only tolerated where it used to be.
	if _, rep := Parse([]byte("trusted_accounts: []\n"), testEnv(), 1); rep.OK() {
		t.Fatal("top-level trusted_accounts accepted")
	}
}

func mustDecode(t *testing.T, yaml string) *document {
	t.Helper()
	d, probs := decode([]byte(yaml))
	if len(probs) > 0 {
		t.Fatal(probs)
	}
	return d
}
