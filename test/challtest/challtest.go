// Package challtest connects the broker's in-memory Route53 fake to Pebble's
// challenge test server (pebble-challtestsrv), so that tests running the
// real upstream adapter against Pebble can use dns01.FakeRoute53: every TXT
// RRset the broker writes to the fake is mirrored to challtestsrv, which is
// the DNS server Pebble validates against.
//
// It is test infrastructure only (used by the `pebble`-tagged end-to-end
// tests and by test/compat's Route53 mock); nothing in the broker imports it.
package challtest

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/route53"
	"github.com/aws/aws-sdk-go-v2/service/route53/types"

	"tls-broker/internal/dns01"
)

// Client talks to challtestsrv's management API (default
// http://127.0.0.1:8055).
type Client struct {
	Base string
	HTTP *http.Client
}

// NewClient returns a client for the management API at base.
func NewClient(base string) *Client {
	return &Client{Base: strings.TrimSuffix(base, "/"), HTTP: &http.Client{Timeout: 10 * time.Second}}
}

func (c *Client) post(ctx context.Context, op string, body map[string]string) error {
	b, _ := json.Marshal(body)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.Base+"/"+op, bytes.NewReader(b))
	if err != nil {
		return err
	}
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return fmt.Errorf("challtestsrv %s: %w", op, err)
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("challtestsrv %s: HTTP %d", op, resp.StatusCode)
	}
	return nil
}

// SetTXT makes the TXT RRset at host exactly values (none removes it).
// challtestsrv only adds single values or clears a host, so this clears and
// re-adds.
func (c *Client) SetTXT(ctx context.Context, host string, values []string) error {
	fq := strings.TrimSuffix(host, ".") + "."
	if err := c.post(ctx, "clear-txt", map[string]string{"host": fq}); err != nil {
		return err
	}
	for _, v := range values {
		if err := c.post(ctx, "set-txt", map[string]string{"host": fq, "value": v}); err != nil {
			return err
		}
	}
	return nil
}

// Route53 is a dns01.Route53API over a FakeRoute53 that mirrors every TXT
// RRset touched by a successful change batch to challtestsrv before the
// change call returns. A failed mirror fails the call (Route53 then looks
// unavailable to the broker, which retries).
type Route53 struct {
	*dns01.FakeRoute53
	Chall *Client
}

var _ dns01.Route53API = (*Route53)(nil)

// ChangeResourceRecordSets implements dns01.Route53API.
func (r *Route53) ChangeResourceRecordSets(ctx context.Context, in *route53.ChangeResourceRecordSetsInput, opts ...func(*route53.Options)) (*route53.ChangeResourceRecordSetsOutput, error) {
	out, err := r.FakeRoute53.ChangeResourceRecordSets(ctx, in, opts...)
	if err != nil {
		return nil, err
	}
	var touched []string
	for _, c := range in.ChangeBatch.Changes {
		if rs := c.ResourceRecordSet; rs != nil && rs.Type == types.RRTypeTxt {
			n := strings.ToLower(strings.TrimSuffix(aws.ToString(rs.Name), "."))
			if !slices.Contains(touched, n) {
				touched = append(touched, n)
			}
		}
	}
	for _, n := range touched {
		if err := r.Chall.SetTXT(context.WithoutCancel(ctx), n, r.FakeRoute53.TXT(n)); err != nil {
			return nil, err
		}
	}
	return out, nil
}
