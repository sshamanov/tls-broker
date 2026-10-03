package app

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/route53"

	"tls-broker/internal/core"
	"tls-broker/internal/dns01"
)

// route53Retry is how soon a Route53 client that could not be built is tried
// again when the engine needs it.
const route53Retry = time.Minute

// route53Switch is the dns01.Route53API the engine holds. It forwards to a
// real client built from the configuration and rebuilds that client when the
// region or the credential secret names change, or when the last build
// failed (for example a credential secret that did not exist yet).
type route53Switch struct {
	secrets core.SecretStore
	clock   core.Clock
	log     *slog.Logger

	mu       sync.Mutex
	cfg      core.Route53Config // what client was built for
	client   dns01.Route53API   // nil when the last build failed
	buildErr error
	builtAt  time.Time
}

var _ dns01.Route53API = (*route53Switch)(nil)

func newRoute53Switch(secrets core.SecretStore, clock core.Clock, log *slog.Logger) *route53Switch {
	return &route53Switch{secrets: secrets, clock: clock, log: log}
}

// clientKey keeps the settings that need a new client.
func clientKey(c core.Route53Config) core.Route53Config {
	return core.Route53Config{Region: c.Region, AccessKeyIDSecret: c.AccessKeyIDSecret, SecretAccessKeySecret: c.SecretAccessKeySecret}
}

// update rebuilds the client when the client settings changed, or when the
// last build failed. With onlyIfChanged false it always builds.
func (s *route53Switch) update(ctx context.Context, cfg core.Route53Config, onlyIfChanged bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if onlyIfChanged && s.client != nil && clientKey(cfg) == s.cfg {
		return
	}
	s.build(ctx, cfg)
}

// build must hold mu.
func (s *route53Switch) build(ctx context.Context, cfg core.Route53Config) {
	s.cfg, s.builtAt = clientKey(cfg), s.clock.Now()
	c, err := dns01.NewRoute53Client(ctx, cfg, s.secrets, s.clock)
	if err != nil {
		s.client, s.buildErr = nil, err
		s.log.Warn("route53 client not available; DNS-01 fails until it is configured", "err", err)
		return
	}
	s.client, s.buildErr = c, nil
	how := "standard AWS credential chain"
	if cfg.AccessKeyIDSecret != "" && cfg.SecretAccessKeySecret != "" {
		how = "credentials from secrets"
	}
	s.log.Info("route53 client ready", "region", cfg.Region, "credentials", how)
}

func (s *route53Switch) current(ctx context.Context) (dns01.Route53API, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.client == nil && s.clock.Now().Sub(s.builtAt) >= route53Retry {
		s.build(ctx, s.cfg)
	}
	if s.client == nil {
		return nil, fmt.Errorf("route53 is not configured: %w", s.buildErr)
	}
	return s.client, nil
}

func (s *route53Switch) ChangeResourceRecordSets(ctx context.Context, in *route53.ChangeResourceRecordSetsInput, optFns ...func(*route53.Options)) (*route53.ChangeResourceRecordSetsOutput, error) {
	c, err := s.current(ctx)
	if err != nil {
		return nil, err
	}
	return c.ChangeResourceRecordSets(ctx, in, optFns...)
}

func (s *route53Switch) ListResourceRecordSets(ctx context.Context, in *route53.ListResourceRecordSetsInput, optFns ...func(*route53.Options)) (*route53.ListResourceRecordSetsOutput, error) {
	c, err := s.current(ctx)
	if err != nil {
		return nil, err
	}
	return c.ListResourceRecordSets(ctx, in, optFns...)
}

func (s *route53Switch) GetChange(ctx context.Context, in *route53.GetChangeInput, optFns ...func(*route53.Options)) (*route53.GetChangeOutput, error) {
	c, err := s.current(ctx)
	if err != nil {
		return nil, err
	}
	return c.GetChange(ctx, in, optFns...)
}

func (s *route53Switch) GetHostedZone(ctx context.Context, in *route53.GetHostedZoneInput, optFns ...func(*route53.Options)) (*route53.GetHostedZoneOutput, error) {
	c, err := s.current(ctx)
	if err != nil {
		return nil, err
	}
	return c.GetHostedZone(ctx, in, optFns...)
}
