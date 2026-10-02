package dns01

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/route53"

	"tls-broker/internal/core"
)

// Route53API is the part of the Route53 client the engine uses. The real
// *route53.Client implements it; FakeRoute53 is the in-memory fake.
type Route53API interface {
	ChangeResourceRecordSets(ctx context.Context, in *route53.ChangeResourceRecordSetsInput, optFns ...func(*route53.Options)) (*route53.ChangeResourceRecordSetsOutput, error)
	ListResourceRecordSets(ctx context.Context, in *route53.ListResourceRecordSetsInput, optFns ...func(*route53.Options)) (*route53.ListResourceRecordSetsOutput, error)
	GetChange(ctx context.Context, in *route53.GetChangeInput, optFns ...func(*route53.Options)) (*route53.GetChangeOutput, error)
	GetHostedZone(ctx context.Context, in *route53.GetHostedZoneInput, optFns ...func(*route53.Options)) (*route53.GetHostedZoneOutput, error)
}

var _ Route53API = (*route53.Client)(nil)

// credentialsRefresh is how long credentials read from the SecretStore are
// cached before they are read again, so a key rotated in the UI is picked up
// without a restart.
const credentialsRefresh = 5 * time.Minute

// NewRoute53Client builds the real Route53 client. When both
// cfg.AccessKeyIDSecret and cfg.SecretAccessKeySecret name secrets, the
// credentials are read from secrets (and re-read every few minutes);
// otherwise the standard AWS credential chain (environment, shared files,
// container or instance role) is used. clock may be nil (system clock).
func NewRoute53Client(ctx context.Context, cfg core.Route53Config, secrets core.SecretStore, clock core.Clock) (*route53.Client, error) {
	if clock == nil {
		clock = core.SystemClock{}
	}
	region := cfg.Region
	if region == "" {
		region = "us-east-1"
	}
	opts := []func(*awsconfig.LoadOptions) error{awsconfig.WithRegion(region)}
	if cfg.AccessKeyIDSecret != "" && cfg.SecretAccessKeySecret != "" {
		if secrets == nil {
			return nil, errors.New("route53: credentials are configured as secrets but no secret store was given")
		}
		p := &secretCredentials{secrets: secrets, idName: cfg.AccessKeyIDSecret, keyName: cfg.SecretAccessKeySecret, clock: clock}
		// Fail early on a missing or empty secret instead of on the first change.
		if _, err := p.Retrieve(ctx); err != nil {
			return nil, err
		}
		opts = append(opts, awsconfig.WithCredentialsProvider(aws.NewCredentialsCache(p)))
	}
	awsCfg, err := awsconfig.LoadDefaultConfig(ctx, opts...)
	if err != nil {
		return nil, fmt.Errorf("route53: load AWS configuration: %w", err)
	}
	return route53.NewFromConfig(awsCfg), nil
}

// secretCredentials reads a static access key from the SecretStore.
type secretCredentials struct {
	secrets         core.SecretStore
	idName, keyName string
	clock           core.Clock
}

// Retrieve implements aws.CredentialsProvider.
func (p *secretCredentials) Retrieve(ctx context.Context) (aws.Credentials, error) {
	id, err := p.secrets.Get(ctx, p.idName)
	if err != nil {
		return aws.Credentials{}, fmt.Errorf("route53: access key id secret %q: %w", p.idName, err)
	}
	key, err := p.secrets.Get(ctx, p.keyName)
	if err != nil {
		return aws.Credentials{}, fmt.Errorf("route53: secret access key secret %q: %w", p.keyName, err)
	}
	ids, keys := strings.TrimSpace(string(id)), strings.TrimSpace(string(key))
	if ids == "" || keys == "" {
		return aws.Credentials{}, errors.New("route53: credential secrets are empty")
	}
	return aws.Credentials{
		AccessKeyID: ids, SecretAccessKey: keys, Source: "tls-broker-secrets",
		CanExpire: true, Expires: p.clock.Now().Add(credentialsRefresh),
	}, nil
}

// hostedZoneID strips the "/hostedzone/" prefix Route53 sometimes returns.
func hostedZoneID(id string) string { return strings.TrimPrefix(id, "/hostedzone/") }

// fqdn returns the record name as Route53 stores it: lower case with a
// trailing dot.
func fqdn(name string) string { return strings.ToLower(strings.TrimSuffix(name, ".")) + "." }

// unfqdn is the inverse of fqdn. Route53 returns some characters as octal
// escapes (\052 for '*'); only that one can occur in names the engine
// handles.
func unfqdn(name string) string {
	return strings.ReplaceAll(strings.ToLower(strings.TrimSuffix(name, ".")), `\052`, "*")
}
