package upstream

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"reflect"
	"slices"
	"sync"
	"time"

	"tls-broker/internal/core"
)

// Registry is the core.Providers of the active configuration. It holds one
// ACMEProvider per configured provider (enabled or disabled) and rebuilds the
// set on Apply. A provider whose definition and the shared upstream timeouts
// did not change keeps its instance, so its loaded key, directory and
// account survive a reload.
type Registry struct {
	opts Options

	mu      sync.RWMutex
	all     map[string]*ACMEProvider
	enabled []core.Provider
	up      core.UpstreamConfig
}

var _ core.Providers = (*Registry)(nil)

// NewRegistry builds the registry for cfg.
func NewRegistry(cfg *core.Config, opts Options) (*Registry, error) {
	r := &Registry{opts: opts, all: map[string]*ACMEProvider{}}
	if err := r.Apply(cfg); err != nil {
		return nil, err
	}
	return r, nil
}

// Apply replaces the provider set with the one of cfg. On error nothing
// changes.
func (r *Registry) Apply(cfg *core.Config) error {
	if cfg == nil {
		return errors.New("upstream: nil configuration")
	}
	r.mu.RLock()
	old, oldUp := r.all, r.up
	r.mu.RUnlock()

	all := make(map[string]*ACMEProvider, len(cfg.Providers))
	var enabled []core.Provider
	for _, pc := range cfg.Providers {
		if _, dup := all[pc.Name]; dup {
			return fmt.Errorf("upstream: provider %q defined twice", pc.Name)
		}
		p := old[pc.Name]
		if p == nil || oldUp != cfg.Upstream || !reflect.DeepEqual(p.cfg, normalizeForCompare(pc)) {
			np, err := NewACMEProvider(pc, cfg.Upstream, r.opts)
			if err != nil {
				return err
			}
			p = np
		}
		all[pc.Name] = p
		if !pc.Disabled {
			enabled = append(enabled, p)
		}
	}
	r.mu.Lock()
	r.all, r.enabled, r.up = all, enabled, cfg.Upstream
	r.mu.Unlock()
	return nil
}

// normalizeForCompare makes a config comparable with the copy a provider
// keeps (nil and empty CAAIssuers are the same).
func normalizeForCompare(pc core.ProviderConfig) core.ProviderConfig {
	pc.CAAIssuers = slices.Clone(pc.CAAIssuers)
	return pc
}

// Follow applies every configuration change of src until ctx is done. A
// configuration the registry cannot use is logged and the previous provider
// set stays active (internal/config validates before activation, so this is
// not expected).
func (r *Registry) Follow(ctx context.Context, src core.ConfigSource) {
	changed, cancel := src.Subscribe()
	defer cancel()
	if err := r.Apply(src.Current()); err != nil {
		slog.Error("upstream: provider configuration not applied", "err", err)
	}
	for {
		select {
		case <-ctx.Done():
			return
		case <-changed:
			if err := r.Apply(src.Current()); err != nil {
				slog.Error("upstream: provider configuration not applied", "err", err)
			}
		}
	}
}

// Get implements core.Providers.
func (r *Registry) Get(name string) (core.Provider, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	p, ok := r.all[name]
	if !ok {
		return nil, false
	}
	return p, true
}

// Enabled implements core.Providers.
func (r *Registry) Enabled() []core.Provider {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return slices.Clone(r.enabled)
}

// Preset is a well-known CA definition that configuration can start from.
type Preset struct {
	Key         string // preset name used in configuration
	Description string
	// Config has Name = Key and every CA fact filled in; the operator adds
	// Contact, EAB and Profile.
	Config core.ProviderConfig
}

// Well-known directory URLs.
const (
	LetsEncryptDirectory        = "https://acme-v02.api.letsencrypt.org/directory"
	LetsEncryptStagingDirectory = "https://acme-staging-v02.api.letsencrypt.org/directory"
	GoogleDirectory             = "https://dv.acme-v02.api.pki.goog/directory"
	GoogleStagingDirectory      = "https://dv.acme-v02.test-api.pki.goog/directory"
)

// Presets returns the well-known CAs (October 2026 facts, docs/providers.md):
//
//   - Let's Encrypt: ARI with rate-limit exemption, CAA accounturi honoured,
//     no EAB.
//   - Google Trust Services: ARI without documented exemption, accounturi
//     support unconfirmed (off), EAB required, 100 newOrder per hour.
func Presets() []Preset {
	le := func(key, dirURL, desc string) Preset {
		return Preset{Key: key, Description: desc, Config: core.ProviderConfig{
			Name: key, DirectoryURL: dirURL, CAAIssuers: []string{"letsencrypt.org"},
			AccountURIHonoured: true, ARI: true, ARIExempt: true, Limits: core.DefaultProviderLimits(),
		}}
	}
	gts := func(key, dirURL, desc string) Preset {
		limits := core.DefaultProviderLimits()
		limits.NewOrders = core.Limit{Count: 60, Window: time.Hour}
		return Preset{Key: key, Description: desc, Config: core.ProviderConfig{
			Name: key, DirectoryURL: dirURL, CAAIssuers: []string{"pki.goog"},
			AccountURIHonoured: false, ARI: true, ARIExempt: false, Limits: limits,
		}}
	}
	return []Preset{
		le("letsencrypt", LetsEncryptDirectory, "Let's Encrypt production"),
		le("letsencrypt-staging", LetsEncryptStagingDirectory, "Let's Encrypt staging (untrusted certificates)"),
		gts("google", GoogleDirectory, "Google Trust Services production (EAB required)"),
		gts("google-staging", GoogleStagingDirectory, "Google Trust Services staging (EAB required, untrusted certificates)"),
	}
}

// PresetConfig returns the preset with that key.
func PresetConfig(key string) (core.ProviderConfig, bool) {
	for _, p := range Presets() {
		if p.Key == key {
			return p.Config, true
		}
	}
	return core.ProviderConfig{}, false
}
