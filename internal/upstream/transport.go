package upstream

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/go-acme/lego/v5/acme"
)

// capture records what the CA answered during one Provider call. lego hides
// response headers when it returns an error, so the transport stores the
// status and Retry-After of the most recent response in the capture carried
// by the request context.
type capture struct {
	mu         sync.Mutex
	status     int    // status of the last response; 0 after a transport error
	retryAfter string // Retry-After header of the last response

	// blockAfterReplaced makes every request after an alreadyReplaced
	// answer fail without being sent. lego's newOrder retries without
	// `replaces` on alreadyReplaced, which would create an order the
	// caller did not ask for.
	blockAfterReplaced bool
	replaced           *acme.ProblemDetails
}

type captureKey struct{}

// errBlockedRetry is what the transport returns instead of sending lego's
// replaces-less newOrder retry.
var errBlockedRetry = errors.New("newOrder retry without replaces suppressed")

func withCapture(ctx context.Context) (context.Context, *capture) {
	c := &capture{}
	return context.WithValue(ctx, captureKey{}, c), c
}

func captureFrom(ctx context.Context) *capture {
	c, _ := ctx.Value(captureKey{}).(*capture)
	return c
}

func (c *capture) snapshot() (status int, retryAfter string, replaced *acme.ProblemDetails) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.status, c.retryAfter, c.replaced
}

// captureTransport fills the capture of each request's context.
type captureTransport struct{ base http.RoundTripper }

func (t *captureTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	c := captureFrom(req.Context())
	if c != nil {
		c.mu.Lock()
		blocked := c.blockAfterReplaced && c.replaced != nil
		c.mu.Unlock()
		if blocked {
			if req.Body != nil {
				_ = req.Body.Close()
			}
			return nil, errBlockedRetry
		}
	}
	resp, err := t.base.RoundTrip(req)
	if c == nil {
		return resp, err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if err != nil {
		c.status, c.retryAfter = 0, ""
		return resp, err
	}
	c.status, c.retryAfter = resp.StatusCode, resp.Header.Get("Retry-After")
	if resp.StatusCode == http.StatusConflict && c.blockAfterReplaced {
		body, rerr := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		_ = resp.Body.Close()
		resp.Body = io.NopCloser(bytes.NewReader(body))
		if rerr == nil {
			var pd acme.ProblemDetails
			if json.Unmarshal(body, &pd) == nil && pd.Type == acme.AlreadyReplacedErrorType {
				if pd.HTTPStatus == 0 {
					pd.HTTPStatus = resp.StatusCode
				}
				c.replaced = &pd
			}
		}
	}
	return resp, nil
}

// newHTTPClient builds the client of one provider: bounded per-request
// timeout, optional private root pool (Pebble), capture transport. Each
// provider gets its own client because lego wraps the client's transport.
func newHTTPClient(timeout time.Duration, roots *x509.CertPool) *http.Client {
	dialer := &net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}
	tr := &http.Transport{
		Proxy:                 http.ProxyFromEnvironment,
		DialContext:           dialer.DialContext,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          10,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: time.Second,
		ResponseHeaderTimeout: timeout,
		TLSClientConfig:       &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: roots},
	}
	return &http.Client{Timeout: timeout, Transport: &captureTransport{base: tr}}
}
