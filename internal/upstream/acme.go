package upstream

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/go-acme/lego/v5/acme"
	"github.com/go-acme/lego/v5/acme/api"

	"tls-broker/internal/core"
	"tls-broker/internal/names"
	"tls-broker/internal/version"
)

// Options are the dependencies shared by every provider.
type Options struct {
	// Secrets holds account keys, account URLs and EAB MAC keys. Required.
	Secrets core.SecretStore
	// Clock drives polling, timeouts and Retry-After dates; nil means
	// core.SystemClock.
	Clock core.Clock
	// RootCAs replaces the system roots for the CA's API endpoint (for
	// Pebble); nil uses the system pool.
	RootCAs *x509.CertPool
	// UserAgent is sent with every request; empty means
	// "tls-broker/<version>".
	UserAgent string
}

// ACMEProvider is a core.Provider for one account at one RFC 8555 CA.
type ACMEProvider struct {
	cfg     core.ProviderConfig
	up      core.UpstreamConfig
	secrets core.SecretStore
	clock   core.Clock
	ua      string
	client  *http.Client

	// sem serializes initialization (key, directory, registration) while
	// staying responsive to ctx.
	sem chan struct{}

	mu         sync.Mutex
	core       *api.Core
	dir        acme.Directory
	accountURL string
}

var _ core.Provider = (*ACMEProvider)(nil)

// keyMu serializes account key creation across provider instances of this
// process, so a registry rebuild racing with first use cannot generate two
// keys for one provider.
var keyMu sync.Mutex

// NewACMEProvider builds the provider for cfg. Nothing is fetched until the
// first call. up supplies the timeouts; zero fields take the defaults of
// core.DefaultConfig.
func NewACMEProvider(cfg core.ProviderConfig, up core.UpstreamConfig, opts Options) (*ACMEProvider, error) {
	if cfg.Name == "" {
		return nil, errors.New("upstream: provider name is empty")
	}
	if opts.Secrets == nil {
		return nil, errors.New("upstream: provider " + cfg.Name + ": no secret store")
	}
	u, err := url.Parse(cfg.DirectoryURL)
	if err != nil || u.Scheme != "https" || u.Host == "" {
		return nil, fmt.Errorf("upstream: provider %s: directory URL %q is not an https URL", cfg.Name, cfg.DirectoryURL)
	}
	if (cfg.EABKeyID == "") != (cfg.EABSecretName == "") {
		return nil, fmt.Errorf("upstream: provider %s: EAB key id and EAB secret name must be set together", cfg.Name)
	}
	def := core.DefaultConfig().Upstream
	if up.HTTPTimeout <= 0 {
		up.HTTPTimeout = def.HTTPTimeout
	}
	if up.ValidationTimeout <= 0 {
		up.ValidationTimeout = def.ValidationTimeout
	}
	if up.IssueTimeout <= 0 {
		up.IssueTimeout = def.IssueTimeout
	}
	if up.PollInterval <= 0 {
		up.PollInterval = def.PollInterval
	}
	clock := opts.Clock
	if clock == nil {
		clock = core.SystemClock{}
	}
	ua := opts.UserAgent
	if ua == "" {
		ua = "tls-broker/" + version.String()
	}
	cfg.CAAIssuers = slices.Clone(cfg.CAAIssuers)
	return &ACMEProvider{
		cfg: cfg, up: up, secrets: opts.Secrets, clock: clock, ua: ua,
		client: newHTTPClient(up.HTTPTimeout, opts.RootCAs),
		sem:    make(chan struct{}, 1),
	}, nil
}

// Name implements core.Provider.
func (p *ACMEProvider) Name() string { return p.cfg.Name }

// Caps implements core.Provider. The capabilities come from configuration
// (presets fill them for the well-known CAs).
func (p *ACMEProvider) Caps() core.ProviderCaps {
	return core.ProviderCaps{ARI: p.cfg.ARI, ARIExempt: p.cfg.ARIExempt,
		CAAIssuers: slices.Clone(p.cfg.CAAIssuers), AccountURIHonoured: p.cfg.AccountURIHonoured}
}

// Config returns the provider's configuration.
func (p *ACMEProvider) Config() core.ProviderConfig {
	c := p.cfg
	c.CAAIssuers = slices.Clone(c.CAAIssuers)
	return c
}

func (p *ACMEProvider) keySecret() string { return core.SecretProviderAccountKeyPrefix + p.cfg.Name }
func (p *ACMEProvider) urlSecret() string { return core.SecretProviderAccountURLPrefix + p.cfg.Name }

func (p *ACMEProvider) lock(ctx context.Context) error {
	select {
	case p.sem <- struct{}{}:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (p *ACMEProvider) unlock() { <-p.sem }

func (p *ACMEProvider) state() (*api.Core, acme.Directory, string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.core, p.dir, p.accountURL
}

// localFailure wraps a failure of local state (secret store) needed to use
// the provider. It is reported as ProviderDown: the provider cannot be used.
func (p *ACMEProvider) localFailure(what string, err error) error {
	return &core.ProviderError{Provider: p.cfg.Name, Kind: core.ProviderDown, Err: fmt.Errorf("%s: %w", what, err)}
}

// ensureCore loads (or creates) the account key, fetches the directory and
// builds the lego client. It does not register the account.
func (p *ACMEProvider) ensureCore(ctx context.Context) (*api.Core, acme.Directory, error) {
	if c, d, _ := p.state(); c != nil {
		return c, d, nil
	}
	if err := p.lock(ctx); err != nil {
		return nil, acme.Directory{}, err
	}
	defer p.unlock()
	if c, d, _ := p.state(); c != nil {
		return c, d, nil
	}

	key, err := p.accountKey(ctx)
	if err != nil {
		return nil, acme.Directory{}, err
	}
	dir, err := p.fetchDirectory(ctx)
	if err != nil {
		return nil, acme.Directory{}, err
	}
	kid := ""
	stored, err := p.secrets.Get(ctx, p.urlSecret())
	switch {
	case err == nil:
		if sameOrigin(strings.TrimSpace(string(stored)), dir.NewAccountURL) {
			kid = strings.TrimSpace(string(stored))
		}
	case !errors.Is(err, core.ErrNotFound):
		return nil, acme.Directory{}, p.localFailure("read account URL", err)
	}

	// api.New fetches the directory again without a context; its HTTP
	// client timeout bounds it, and ctx is honoured by not waiting.
	type result struct {
		c   *api.Core
		err error
	}
	done := make(chan result, 1)
	go func() {
		c, err := api.New(p.client, p.ua, p.cfg.DirectoryURL, kid, key)
		done <- result{c, err}
	}()
	var r result
	select {
	case r = <-done:
	case <-ctx.Done():
		return nil, acme.Directory{}, ctx.Err()
	}
	if r.err != nil {
		return nil, acme.Directory{}, p.classify(ctx, nil, r.err)
	}
	p.mu.Lock()
	p.core, p.dir, p.accountURL = r.c, dir, kid
	p.mu.Unlock()
	return r.c, dir, nil
}

// sameOrigin reports whether two URLs share scheme and host, so a stored
// account URL is only used with the CA it was registered at.
func sameOrigin(a, b string) bool {
	ua, err1 := url.Parse(a)
	ub, err2 := url.Parse(b)
	return err1 == nil && err2 == nil && ua.Host != "" && ua.Scheme == ub.Scheme && strings.EqualFold(ua.Host, ub.Host)
}

// fetchDirectory GETs the directory with ctx and the capture, so a CA that
// is down or busy is classified like any other call.
func (p *ACMEProvider) fetchDirectory(ctx context.Context) (acme.Directory, error) {
	cctx, c := withCapture(ctx)
	var dir acme.Directory
	req, err := http.NewRequestWithContext(cctx, http.MethodGet, p.cfg.DirectoryURL, nil)
	if err != nil {
		return dir, p.down("directory request: %v", err)
	}
	req.Header.Set("User-Agent", p.ua)
	resp, err := p.client.Do(req)
	if err != nil {
		return dir, p.classify(ctx, c, err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode >= 400 {
		var pd acme.ProblemDetails
		if json.NewDecoder(resp.Body).Decode(&pd) == nil && pd.Type != "" {
			if pd.HTTPStatus == 0 {
				pd.HTTPStatus = resp.StatusCode
			}
			return dir, p.classify(ctx, c, &pd)
		}
		return dir, p.classify(ctx, c, fmt.Errorf("directory: HTTP %d", resp.StatusCode))
	}
	if err := json.NewDecoder(resp.Body).Decode(&dir); err != nil {
		return dir, p.down("directory: %v", err)
	}
	if dir.NewAccountURL == "" || dir.NewOrderURL == "" || dir.NewNonceURL == "" {
		return dir, p.down("directory at %s is incomplete", p.cfg.DirectoryURL)
	}
	return dir, nil
}

// accountKey returns the stored account key, creating and storing an ECDSA
// P-256 key only when none exists. An existing key is never replaced: the
// account (ARI continuity, single-use EAB) hangs on it.
func (p *ACMEProvider) accountKey(ctx context.Context) (crypto.Signer, error) {
	keyMu.Lock()
	defer keyMu.Unlock()
	raw, err := p.secrets.Get(ctx, p.keySecret())
	if err == nil {
		k, perr := parseKey(raw)
		if perr != nil {
			return nil, p.localFailure("account key "+p.keySecret(), perr)
		}
		return k, nil
	}
	if !errors.Is(err, core.ErrNotFound) {
		return nil, p.localFailure("read account key", err)
	}
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, p.localFailure("generate account key", err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(k)
	if err != nil {
		return nil, p.localFailure("encode account key", err)
	}
	if err := p.secrets.Put(ctx, p.keySecret(), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})); err != nil {
		return nil, p.localFailure("store account key", err)
	}
	return k, nil
}

// parseKey reads a PEM private key: PKCS#8 (what the broker writes), or SEC 1
// EC / PKCS#1 RSA keys imported by an operator.
func parseKey(raw []byte) (crypto.Signer, error) {
	block, _ := pem.Decode(raw)
	if block == nil {
		return nil, errors.New("no PEM block")
	}
	var k any
	var err error
	switch block.Type {
	case "EC PRIVATE KEY":
		k, err = x509.ParseECPrivateKey(block.Bytes)
	case "RSA PRIVATE KEY":
		k, err = x509.ParsePKCS1PrivateKey(block.Bytes)
	default:
		k, err = x509.ParsePKCS8PrivateKey(block.Bytes)
	}
	if err != nil {
		return nil, err
	}
	switch s := k.(type) {
	case *ecdsa.PrivateKey:
		return s, nil
	case *rsa.PrivateKey:
		return s, nil
	}
	return nil, fmt.Errorf("unsupported account key type %T", k)
}

// AccountURL implements core.Provider.
func (p *ACMEProvider) AccountURL(ctx context.Context) (string, error) {
	_, u, err := p.ensureAccount(ctx)
	return u, err
}

// ensureAccount returns the client with a registered account.
func (p *ACMEProvider) ensureAccount(ctx context.Context) (*api.Core, string, error) {
	if c, _, u := p.state(); c != nil && u != "" {
		return c, u, nil
	}
	c, _, err := p.ensureCore(ctx)
	if err != nil {
		return nil, "", err
	}
	if err := p.lock(ctx); err != nil {
		return nil, "", err
	}
	defer p.unlock()
	if _, _, u := p.state(); u != "" {
		return c, u, nil
	}

	acct := acme.Account{TermsOfServiceAgreed: true}
	if p.cfg.Contact != "" {
		contact := p.cfg.Contact
		if !strings.HasPrefix(contact, "mailto:") {
			contact = "mailto:" + contact
		}
		acct.Contact = []string{contact}
	}
	cctx, cp := withCapture(ctx)
	var ext acme.ExtendedAccount
	if p.cfg.EABKeyID != "" {
		mac, gerr := p.secrets.Get(ctx, p.cfg.EABSecretName)
		if gerr != nil {
			if errors.Is(gerr, core.ErrNotFound) {
				return nil, "", p.rejected(core.NewProblem(core.ProblemExternalAccountRequired,
					"EAB secret %q is not set", p.cfg.EABSecretName))
			}
			return nil, "", p.localFailure("read EAB secret", gerr)
		}
		ext, err = c.Accounts.NewEAB(cctx, acct, p.cfg.EABKeyID, strings.TrimSpace(string(mac)))
	} else {
		ext, err = c.Accounts.New(cctx, acct)
	}
	if err != nil {
		return nil, "", p.classify(ctx, cp, err)
	}
	if ext.Location == "" {
		return nil, "", p.down("newAccount answered without a Location")
	}
	if err := p.secrets.Put(ctx, p.urlSecret(), []byte(ext.Location)); err != nil {
		return nil, "", p.localFailure("store account URL", err)
	}
	p.mu.Lock()
	p.accountURL = ext.Location
	p.mu.Unlock()
	return c, ext.Location, nil
}

// NewOrder implements core.Provider.
func (p *ACMEProvider) NewOrder(ctx context.Context, orderNames []string, replaces string) (core.UpstreamOrder, error) {
	c, _, err := p.ensureAccount(ctx)
	if err != nil {
		return core.UpstreamOrder{}, err
	}
	if len(orderNames) == 0 {
		return core.UpstreamOrder{}, p.rejected(core.NewProblem(core.ProblemMalformed, "order has no identifiers"))
	}
	_, dir, _ := p.state()
	if replaces != "" && (!p.cfg.ARI || dir.RenewalInfo == "") {
		return core.UpstreamOrder{}, p.rejected(core.NewProblem(core.ProblemMalformed, "provider %s does not support replaces", p.cfg.Name))
	}
	cctx, cp := withCapture(ctx)
	cp.blockAfterReplaced = true
	ext, err := c.Orders.New(cctx, orderNames, &api.OrderOptions{Profile: p.cfg.Profile, ReplacesCertID: replaces})
	if err != nil {
		return core.UpstreamOrder{}, p.classify(ctx, cp, err)
	}
	if ext.Location == "" {
		return core.UpstreamOrder{}, p.down("newOrder answered without a Location")
	}
	o := toUpstream(ext.Order, ext.Location)
	if o.Replaces == "" {
		o.Replaces = replaces
	}
	return o, nil
}

func toUpstream(o acme.Order, orderURL string) core.UpstreamOrder {
	u := core.UpstreamOrder{
		URL: orderURL, Status: core.UpstreamStatus(o.Status), Replaces: o.Replaces,
		AuthorizationURLs: slices.Clone(o.Authorizations), FinalizeURL: o.Finalize, CertificateURL: o.Certificate,
		Error: toProblem(o.Error),
	}
	if o.Expires != "" {
		if t, err := time.Parse(time.RFC3339, o.Expires); err == nil {
			u.Expires = t.UTC()
		}
	}
	for _, id := range o.Identifiers {
		u.Names = append(u.Names, id.Value)
	}
	return u
}

// getOrder fetches an order and the Retry-After of the answer.
func (p *ACMEProvider) getOrder(ctx context.Context, orderURL string) (core.UpstreamOrder, time.Duration, error) {
	c, _, err := p.ensureAccount(ctx)
	if err != nil {
		return core.UpstreamOrder{}, 0, err
	}
	cctx, cp := withCapture(ctx)
	ext, err := c.Orders.Get(cctx, orderURL)
	if err != nil {
		return core.UpstreamOrder{}, 0, p.classify(ctx, cp, err)
	}
	_, ra, _ := cp.snapshot()
	return toUpstream(ext.Order, orderURL), parseRetryAfter(ra, p.clock.Now()), nil
}

// GetOrder implements core.Provider.
func (p *ACMEProvider) GetOrder(ctx context.Context, orderURL string) (core.UpstreamOrder, error) {
	o, _, err := p.getOrder(ctx, orderURL)
	return o, err
}

// DNSChallenges implements core.Provider. A wildcard and its base name have
// separate authorizations at the CA but the same record name; both are
// returned and both values must be published.
func (p *ACMEProvider) DNSChallenges(ctx context.Context, order core.UpstreamOrder) ([]core.UpstreamChallenge, error) {
	c, _, err := p.ensureAccount(ctx)
	if err != nil {
		return nil, err
	}
	authzURLs := order.AuthorizationURLs
	if len(authzURLs) == 0 && order.URL != "" {
		o, err := p.GetOrder(ctx, order.URL)
		if err != nil {
			return nil, err
		}
		authzURLs = o.AuthorizationURLs
	}
	var out []core.UpstreamChallenge
	for _, au := range authzURLs {
		cctx, cp := withCapture(ctx)
		az, err := c.Authorizations.Get(cctx, au)
		if err != nil {
			return nil, p.classify(ctx, cp, err)
		}
		ident := names.Base(az.Identifier.Value)
		if n, nerr := names.Normalize(ident); nerr == nil {
			ident = n
		}
		wildcard := az.Wildcard || names.IsWildcard(az.Identifier.Value)
		switch az.Status {
		case acme.StatusValid:
			continue
		case acme.StatusPending:
		default:
			prob := core.NewProblem(core.ProblemUnauthorized, "authorization for %s is %s", az.Identifier.Value, az.Status)
			for _, ch := range az.Challenges {
				if ch.Error != nil {
					prob = toProblem(ch.Error)
					break
				}
			}
			return nil, p.rejected(prob)
		}
		var dns *acme.Challenge
		for i := range az.Challenges {
			if az.Challenges[i].Type == "dns-01" {
				dns = &az.Challenges[i]
				break
			}
		}
		if dns == nil {
			return nil, p.rejected(core.NewProblem(core.ProblemMalformed, "authorization for %s offers no dns-01 challenge", az.Identifier.Value))
		}
		keyAuth, err := c.GetKeyAuthorization(dns.Token)
		if err != nil {
			return nil, p.down("key authorization: %v", err)
		}
		sum := sha256.Sum256([]byte(keyAuth))
		out = append(out, core.UpstreamChallenge{
			AuthorizationURL: au, URL: dns.URL, Identifier: ident, Wildcard: wildcard,
			RecordName: names.ChallengeRecord(ident), Value: base64.RawURLEncoding.EncodeToString(sum[:]),
		})
	}
	return out, nil
}

// Accept implements core.Provider.
func (p *ACMEProvider) Accept(ctx context.Context, ch core.UpstreamChallenge) error {
	c, _, err := p.ensureAccount(ctx)
	if err != nil {
		return err
	}
	cctx, cp := withCapture(ctx)
	cur, err := c.Challenges.Get(cctx, ch.URL)
	if err != nil {
		return p.classify(ctx, cp, err)
	}
	if cur.Status != acme.StatusPending {
		return nil
	}
	cctx, cp = withCapture(ctx)
	if _, err := c.Challenges.New(cctx, ch.URL); err != nil {
		perr := p.classify(ctx, cp, err)
		// Someone (a retry, a concurrent caller) got there first.
		if pe := core.AsProviderError(perr); pe != nil && pe.Kind == core.ProviderRejected {
			if again, gerr := c.Challenges.Get(ctx, ch.URL); gerr == nil && again.Status != acme.StatusPending {
				return nil
			}
		}
		return perr
	}
	return nil
}

// poll fetches the order until check reports done, honouring Retry-After
// (else PollInterval) and giving up with ProviderDown after timeout.
func (p *ACMEProvider) poll(ctx context.Context, orderURL string, timeout time.Duration, what string,
	check func(core.UpstreamOrder) (bool, error)) (core.UpstreamOrder, error) {
	deadline := p.clock.Now().Add(timeout)
	for {
		o, ra, err := p.getOrder(ctx, orderURL)
		if err != nil {
			return core.UpstreamOrder{}, err
		}
		if done, err := check(o); done || err != nil {
			return o, err
		}
		now := p.clock.Now()
		if !now.Before(deadline) {
			return core.UpstreamOrder{}, p.down("order %s still %s after %s waiting for %s", orderURL, o.Status, timeout, what)
		}
		wait := ra
		if wait <= 0 {
			wait = p.up.PollInterval
		}
		wait = min(wait, deadline.Sub(now))
		if err := core.Sleep(ctx, p.clock, wait); err != nil {
			return core.UpstreamOrder{}, err
		}
	}
}

// orderProblem is the problem of an invalid order: its own error, else the
// first failed challenge of its authorizations.
func (p *ACMEProvider) orderProblem(ctx context.Context, o core.UpstreamOrder) *core.Problem {
	if o.Error != nil {
		return o.Error
	}
	if c, _, _ := p.state(); c != nil {
		for _, au := range o.AuthorizationURLs {
			az, err := c.Authorizations.Get(ctx, au)
			if err != nil {
				break
			}
			for _, ch := range az.Challenges {
				if ch.Error != nil {
					return toProblem(ch.Error)
				}
			}
		}
	}
	return core.NewProblem(core.ProblemMalformed, "order %s is invalid", o.URL)
}

// WaitReady implements core.Provider.
func (p *ACMEProvider) WaitReady(ctx context.Context, orderURL string) (core.UpstreamOrder, error) {
	return p.poll(ctx, orderURL, p.up.ValidationTimeout, "validation", func(o core.UpstreamOrder) (bool, error) {
		switch o.Status {
		case core.UpstreamPending:
			return false, nil
		case core.UpstreamInvalid:
			return true, p.rejected(p.orderProblem(ctx, o))
		}
		return true, nil
	})
}

// Finalize implements core.Provider. The order's state is read first: a
// ready order gets the CSR; a processing or valid one is returned as it is
// (for a valid one the certificate's key must match the CSR's).
func (p *ACMEProvider) Finalize(ctx context.Context, orderURL string, csrDER []byte) (core.UpstreamOrder, error) {
	csr, err := x509.ParseCertificateRequest(csrDER)
	if err != nil {
		return core.UpstreamOrder{}, p.rejected(core.NewProblem(core.ProblemBadCSR, "cannot parse CSR: %v", err))
	}
	o, _, err := p.getOrder(ctx, orderURL)
	if err != nil {
		return core.UpstreamOrder{}, err
	}
	if o.Status == core.UpstreamReady {
		c, _, _ := p.state()
		cctx, cp := withCapture(ctx)
		ext, ferr := c.Orders.UpdateForCSR(cctx, o.FinalizeURL, csrDER)
		if ferr == nil {
			return toUpstream(ext.Order, orderURL), nil
		}
		perr := p.classify(ctx, cp, ferr)
		pe := core.AsProviderError(perr)
		if pe == nil || pe.Problem == nil || pe.Problem.Type != core.ProblemOrderNotReady {
			return core.UpstreamOrder{}, perr
		}
		// orderNotReady: maybe an earlier attempt already went through.
		o, _, err = p.getOrder(ctx, orderURL)
		if err != nil {
			return core.UpstreamOrder{}, err
		}
		if o.Status != core.UpstreamProcessing && o.Status != core.UpstreamValid {
			return core.UpstreamOrder{}, perr
		}
	}
	switch o.Status {
	case core.UpstreamProcessing:
		return o, nil
	case core.UpstreamValid:
		chain, err := p.fetchChain(ctx, o.CertificateURL)
		if err != nil {
			return core.UpstreamOrder{}, err
		}
		if !samePublicKey(chain, csr.PublicKey) {
			return core.UpstreamOrder{}, p.rejected(core.NewProblem(core.ProblemOrderNotReady, "order was already finalized with another CSR"))
		}
		return o, nil
	case core.UpstreamInvalid:
		return core.UpstreamOrder{}, p.rejected(p.orderProblem(ctx, o))
	}
	return core.UpstreamOrder{}, p.rejected(core.NewProblem(core.ProblemOrderNotReady, "order is %s", o.Status))
}

func samePublicKey(chainPEM []byte, pub any) bool {
	block, _ := pem.Decode(chainPEM)
	if block == nil {
		return false
	}
	leaf, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return false
	}
	k, ok := leaf.PublicKey.(interface{ Equal(crypto.PublicKey) bool })
	return ok && k.Equal(pub)
}

// WaitCertificate implements core.Provider.
func (p *ACMEProvider) WaitCertificate(ctx context.Context, orderURL string) ([]byte, error) {
	o, err := p.poll(ctx, orderURL, p.up.IssueTimeout, "issuance", func(o core.UpstreamOrder) (bool, error) {
		switch o.Status {
		case core.UpstreamValid:
			return true, nil
		case core.UpstreamProcessing:
			return false, nil
		case core.UpstreamInvalid:
			return true, p.rejected(p.orderProblem(ctx, o))
		}
		return true, p.rejected(core.NewProblem(core.ProblemOrderNotReady, "order is %s and was not finalized", o.Status))
	})
	if err != nil {
		return nil, err
	}
	return p.fetchChain(ctx, o.CertificateURL)
}

// fetchChain downloads the certificate and returns leaf plus intermediates
// as PEM, dropping any self-signed (root) certificate the CA included.
func (p *ACMEProvider) fetchChain(ctx context.Context, certURL string) ([]byte, error) {
	if certURL == "" {
		return nil, p.down("valid order without certificate URL")
	}
	c, _, err := p.ensureAccount(ctx)
	if err != nil {
		return nil, err
	}
	cctx, cp := withCapture(ctx)
	raw, err := c.Certificates.Get(cctx, certURL, true)
	if err != nil {
		return nil, p.classify(ctx, cp, err)
	}
	var out bytes.Buffer
	rest := raw.Cert
	n := 0
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, p.down("certificate chain: %v", err)
		}
		if n > 0 && isSelfSigned(cert) {
			continue
		}
		_ = pem.Encode(&out, &pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
		n++
	}
	if n == 0 {
		return nil, p.down("certificate download contained no certificate")
	}
	return out.Bytes(), nil
}

func isSelfSigned(c *x509.Certificate) bool {
	return bytes.Equal(c.RawIssuer, c.RawSubject) && c.CheckSignatureFrom(c) == nil
}

// RenewalInfo implements core.Provider. It needs no account: the renewalInfo
// resource is fetched with a plain GET.
func (p *ACMEProvider) RenewalInfo(ctx context.Context, ariCertID string) (core.RenewalInfo, error) {
	if !p.cfg.ARI {
		return core.RenewalInfo{}, p.rejected(core.NewProblem(core.ProblemMalformed, "provider %s does not serve renewal information", p.cfg.Name))
	}
	if ariCertID == "" {
		return core.RenewalInfo{}, p.rejected(core.NewProblem(core.ProblemMalformed, "empty certificate identifier"))
	}
	c, dir, err := p.ensureCore(ctx)
	if err != nil {
		return core.RenewalInfo{}, err
	}
	if dir.RenewalInfo == "" {
		return core.RenewalInfo{}, p.rejected(core.NewProblem(core.ProblemMalformed, "provider %s does not advertise renewalInfo", p.cfg.Name))
	}
	cctx, cp := withCapture(ctx)
	info, err := c.Certificates.GetRenewalInfo(cctx, ariCertID)
	if err != nil {
		return core.RenewalInfo{}, p.classify(ctx, cp, err)
	}
	_, ra, _ := cp.snapshot()
	return core.RenewalInfo{
		WindowStart: info.SuggestedWindow.Start.UTC(), WindowEnd: info.SuggestedWindow.End.UTC(),
		ExplanationURL: info.ExplanationURL, RetryAfter: parseRetryAfter(ra, p.clock.Now()),
	}, nil
}
