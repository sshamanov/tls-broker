package upstream

import (
	"context"
	"net/http"
	"testing"
	"time"

	"tls-broker/internal/core"
	"tls-broker/internal/core/coretest"
)

func TestParseRetryAfter(t *testing.T) {
	now := time.Date(2026, 10, 2, 12, 0, 0, 0, time.UTC)
	cases := map[string]time.Duration{
		"":               0,
		"  ":             0,
		"0":              0,
		"-5":             0,
		"120":            2 * time.Minute,
		" 7 ":            7 * time.Second,
		"99999999999999": maxRetryAfter,
		"soon":           0,
		now.Add(time.Hour).Format(http.TimeFormat):                  time.Hour,
		now.Add(-time.Hour).Format(http.TimeFormat):                 0,
		now.Add(30 * time.Second).Format(time.RFC850):               30 * time.Second, // obsolete form
		now.Add(45 * time.Second).Format(time.ANSIC):                45 * time.Second, // asctime form
		now.Add(400 * 24 * time.Hour).UTC().Format(http.TimeFormat): maxRetryAfter,
		"Fri, 02 Oct 2026 12:00:10 GMT":                             10 * time.Second,
	}
	for in, want := range cases {
		if got := parseRetryAfter(in, now); got != want {
			t.Errorf("parseRetryAfter(%q) = %s, want %s", in, got, want)
		}
	}
}

func testConfig(dirURL string) *core.Config {
	cfg := core.DefaultConfig()
	cfg.Providers = []core.ProviderConfig{
		{Name: "primary", DirectoryURL: dirURL, ARI: true, ARIExempt: true, CAAIssuers: []string{"primary.test"}},
		{Name: "off", DirectoryURL: dirURL, Disabled: true},
		{Name: "fallback", DirectoryURL: dirURL, ARI: true},
	}
	return cfg
}

func providerNames(ps []core.Provider) []string {
	var out []string
	for _, p := range ps {
		out = append(out, p.Name())
	}
	return out
}

func TestRegistry(t *testing.T) {
	ca := newStubCA(t)
	opts := Options{Secrets: coretest.NewFakeSecrets(), RootCAs: ca.roots()}
	cfg := testConfig(ca.dirURL())
	r, err := NewRegistry(cfg, opts)
	if err != nil {
		t.Fatal(err)
	}
	if got := providerNames(r.Enabled()); len(got) != 2 || got[0] != "primary" || got[1] != "fallback" {
		t.Fatalf("enabled = %v", got)
	}
	off, ok := r.Get("off")
	if !ok || off.Name() != "off" {
		t.Fatal("disabled provider not returned by Get")
	}
	if _, ok := r.Get("nope"); ok {
		t.Fatal("unknown provider found")
	}
	prim, _ := r.Get("primary")
	if c := prim.Caps(); !c.ARI || !c.ARIExempt || c.AccountURIHonoured || c.CAAIssuers[0] != "primary.test" {
		t.Fatalf("caps = %+v", c)
	}
	if _, err := prim.AccountURL(ctxT(t)); err != nil {
		t.Fatal(err)
	}

	// Reload: unchanged providers keep their instance (and account state),
	// changed ones are rebuilt, order follows the configuration.
	cfg2 := testConfig(ca.dirURL())
	cfg2.Providers = []core.ProviderConfig{cfg.Providers[2], cfg.Providers[0], {Name: "off", DirectoryURL: ca.dirURL(), Contact: "x@example.com"}}
	if err := r.Apply(cfg2); err != nil {
		t.Fatal(err)
	}
	if got := providerNames(r.Enabled()); len(got) != 3 || got[0] != "fallback" || got[1] != "primary" || got[2] != "off" {
		t.Fatalf("enabled after reload = %v", got)
	}
	prim2, _ := r.Get("primary")
	if prim2 != prim {
		t.Fatal("unchanged provider was rebuilt")
	}
	off2, _ := r.Get("off")
	if off2 == off {
		t.Fatal("changed provider was not rebuilt")
	}

	// Changed timeouts rebuild everything.
	cfg3 := testConfig(ca.dirURL())
	cfg3.Providers = cfg2.Providers
	cfg3.Upstream.PollInterval = time.Second
	if err := r.Apply(cfg3); err != nil {
		t.Fatal(err)
	}
	if prim3, _ := r.Get("primary"); prim3 == prim {
		t.Fatal("provider kept after upstream timeouts changed")
	}

	// Invalid configuration: error, nothing changes.
	bad := testConfig(ca.dirURL())
	bad.Providers = append(bad.Providers, core.ProviderConfig{Name: "primary", DirectoryURL: ca.dirURL()})
	if err := r.Apply(bad); err == nil {
		t.Fatal("duplicate provider accepted")
	}
	bad.Providers = []core.ProviderConfig{{Name: "x", DirectoryURL: "http://insecure.test/dir"}}
	if err := r.Apply(bad); err == nil {
		t.Fatal("http directory accepted")
	}
	if got := providerNames(r.Enabled()); len(got) != 3 {
		t.Fatalf("failed apply changed the set: %v", got)
	}
	if _, err := NewRegistry(nil, opts); err == nil {
		t.Fatal("nil config accepted")
	}
}

func TestRegistryFollow(t *testing.T) {
	ca := newStubCA(t)
	src := coretest.NewFakeConfig(testConfig(ca.dirURL()))
	r, err := NewRegistry(src.Current(), Options{Secrets: coretest.NewFakeSecrets(), RootCAs: ca.roots()})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { r.Follow(ctx, src); close(done) }()

	src.Update(func(c *core.Config) {
		c.Providers = []core.ProviderConfig{{Name: "only", DirectoryURL: ca.dirURL()}}
	})
	deadline := time.Now().Add(5 * time.Second)
	for {
		if got := providerNames(r.Enabled()); len(got) == 1 && got[0] == "only" {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("registry did not follow the change: %v", providerNames(r.Enabled()))
		}
		time.Sleep(10 * time.Millisecond)
	}
	cancel()
	<-done
}

func TestPresets(t *testing.T) {
	want := map[string]struct {
		dir             string
		issuer          string
		exempt, account bool
	}{
		"letsencrypt":         {LetsEncryptDirectory, "letsencrypt.org", true, true},
		"letsencrypt-staging": {LetsEncryptStagingDirectory, "letsencrypt.org", true, true},
		"google":              {GoogleDirectory, "pki.goog", false, false},
		"google-staging":      {GoogleStagingDirectory, "pki.goog", false, false},
	}
	ps := Presets()
	if len(ps) != len(want) {
		t.Fatalf("presets = %d", len(ps))
	}
	for _, p := range ps {
		w, ok := want[p.Key]
		if !ok {
			t.Fatalf("unexpected preset %q", p.Key)
		}
		c := p.Config
		if c.Name != p.Key || c.DirectoryURL != w.dir || c.CAAIssuers[0] != w.issuer || !c.ARI ||
			c.ARIExempt != w.exempt || c.AccountURIHonoured != w.account || c.Limits.Concurrency < 1 || p.Description == "" {
			t.Fatalf("preset %s = %+v", p.Key, c)
		}
		if _, err := NewACMEProvider(c, core.UpstreamConfig{}, Options{Secrets: coretest.NewFakeSecrets()}); err != nil {
			t.Fatalf("preset %s: %v", p.Key, err)
		}
	}
	g, ok := PresetConfig("google")
	if !ok || g.Limits.NewOrders.Count >= 100 || g.Limits.NewOrders.Window != time.Hour {
		t.Fatalf("google limits = %+v", g.Limits.NewOrders)
	}
	if _, ok := PresetConfig("zerossl"); ok {
		t.Fatal("unknown preset found")
	}
	// Presets are fresh copies.
	g.CAAIssuers[0] = "changed"
	if g2, _ := PresetConfig("google"); g2.CAAIssuers[0] != "pki.goog" {
		t.Fatal("preset shared state")
	}
}
