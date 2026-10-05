// Package ctlog keeps an in-memory inventory of every certificate that
// Certificate Transparency logs show for the managed zones, no matter who
// requested it (the broker, the operator's own ACME clients, anyone), and
// derives from it the state of each identifier set: ok, renewal due,
// overdue, expired, replaced, revoked, issued by a CA the zone's CAA does
// not allow. See architecture.md §31.
//
// The data comes from a Source (SSLMate Cert Spotter in production, a fake
// in tests). Nothing is persisted: the first refresh runs at startup, later
// ones every ct_inventory.interval, continuing from the source's cursor so
// a routine refresh costs one or two requests per zone.
package ctlog

import (
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"

	"tls-broker/internal/names"
)

// Issuance is one certificate as Certificate Transparency shows it. A
// precertificate and its final certificate are one issuance (same
// TBSSHA256).
type Issuance struct {
	// ID is the source's opaque identifier; it orders issuances by
	// discovery and is the cursor of the next query.
	ID string
	// TBSSHA256 identifies the issuance (RFC 6962 TBSCertificate without
	// SCT and poison extensions): a precertificate and its certificate
	// share it.
	TBSSHA256  string
	CertSHA256 string
	// Serial is lowercase hex without leading zeros, like
	// core.Certificate.Serial; "" when the source gave no certificate.
	Serial string
	// Names are the DNS names, normalized (lower case), sorted, unique.
	Names               []string
	NotBefore, NotAfter time.Time
	// Issuer is the CA organisation ("Let's Encrypt"), IssuerDN the
	// issuer's distinguished name.
	Issuer, IssuerDN string
	// IssuerCAA are the CAA issuer domains that authorize this CA
	// ("letsencrypt.org"); empty when the source does not know them.
	IssuerCAA []string
	Revoked   bool
}

// Key is the identifier-set key: the sorted names joined by commas.
func (i Issuance) Key() string { return strings.Join(i.Names, ",") }

// Source lists the issuances for a domain and all its subdomains.
type Source interface {
	// List returns the next page of unexpired issuances for domain (and
	// every name below it, wildcards included) that the source discovered
	// after the issuance with ID after ("" starts at the oldest). An empty
	// page means the caller has seen everything. A *RateLimitError means
	// the source refused the request for now.
	List(ctx context.Context, domain, after string) ([]Issuance, error)
}

// RateLimitError is a refusal by the source because of its request limit.
type RateLimitError struct {
	RetryAfter time.Duration // 0 when the source did not say
	Message    string
}

func (e *RateLimitError) Error() string {
	msg := "rate limited by the Certificate Transparency source"
	if e.Message != "" {
		msg += ": " + e.Message
	}
	if e.RetryAfter > 0 {
		msg += fmt.Sprintf(" (retry after %s)", e.RetryAfter)
	}
	return msg
}

// CertSpotterURL is the Cert Spotter API endpoint for issuances.
const CertSpotterURL = "https://api.certspotter.com/v1/issuances"

// CertSpotter is the Source backed by SSLMate's Cert Spotter API v1,
// unauthenticated. Without an API key SSLMate allows a small number of
// full-domain queries per hour (core.CTQueriesPerHour; every page,
// including the final empty one, is a query) and returns only unexpired
// issuances.
type CertSpotter struct {
	// Endpoint defaults to CertSpotterURL.
	Endpoint string
	// Client defaults to a client with a 30 s timeout.
	Client    *http.Client
	UserAgent string
}

// maxBody bounds one response; a page holds at most a few hundred
// issuances of a few kilobytes each.
const maxBody = 16 << 20

// List implements Source.
func (c *CertSpotter) List(ctx context.Context, domain, after string) ([]Issuance, error) {
	endpoint := c.Endpoint
	if endpoint == "" {
		endpoint = CertSpotterURL
	}
	q := url.Values{}
	q.Set("domain", domain)
	q.Set("include_subdomains", "true")
	q.Set("match_wildcards", "true")
	for _, e := range []string{"dns_names", "issuer", "issuer.caa_domains", "cert_der"} {
		q.Add("expand", e)
	}
	if after != "" {
		q.Set("after", after)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint+"?"+q.Encode(), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	if c.UserAgent != "" {
		req.Header.Set("User-Agent", c.UserAgent)
	}
	client := c.Client
	if client == nil {
		client = &http.Client{Timeout: 30 * time.Second}
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBody))
	if err != nil {
		return nil, fmt.Errorf("read Cert Spotter response: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		var apiErr struct {
			Code    string `json:"code"`
			Message string `json:"message"`
		}
		_ = json.Unmarshal(body, &apiErr)
		if resp.StatusCode == http.StatusTooManyRequests || apiErr.Code == "rate_limited" {
			return nil, &RateLimitError{RetryAfter: retryAfter(resp.Header.Get("Retry-After")), Message: apiErr.Message}
		}
		msg := apiErr.Message
		if msg == "" {
			msg = strings.TrimSpace(string(body[:min(len(body), 200)]))
		}
		return nil, fmt.Errorf("Cert Spotter answered %s: %s", resp.Status, msg)
	}
	return ParseCertSpotter(body)
}

func retryAfter(v string) time.Duration {
	if s, err := strconv.Atoi(strings.TrimSpace(v)); err == nil && s > 0 {
		return time.Duration(s) * time.Second
	}
	return 0
}

type csIssuance struct {
	ID         string   `json:"id"`
	TBSSHA256  string   `json:"tbs_sha256"`
	CertSHA256 string   `json:"cert_sha256"`
	DNSNames   []string `json:"dns_names"`
	NotBefore  string   `json:"not_before"`
	NotAfter   string   `json:"not_after"`
	Revoked    *bool    `json:"revoked"`
	CertDER    string   `json:"cert_der"`
	Issuer     *struct {
		FriendlyName string   `json:"friendly_name"`
		Name         string   `json:"name"`
		CAADomains   []string `json:"caa_domains"`
	} `json:"issuer"`
}

// ParseCertSpotter decodes one Cert Spotter issuances page (a JSON array of
// issuance objects with dns_names, issuer, issuer.caa_domains and cert_der
// expanded).
func ParseCertSpotter(body []byte) ([]Issuance, error) {
	var raw []csIssuance
	if err := json.Unmarshal(body, &raw); err != nil {
		return nil, fmt.Errorf("decode Cert Spotter response: %w", err)
	}
	out := make([]Issuance, 0, len(raw))
	for _, r := range raw {
		if r.ID == "" || r.TBSSHA256 == "" {
			return nil, errors.New("decode Cert Spotter response: issuance without id or tbs_sha256")
		}
		nb, err1 := time.Parse(time.RFC3339, r.NotBefore)
		na, err2 := time.Parse(time.RFC3339, r.NotAfter)
		if err := errors.Join(err1, err2); err != nil {
			return nil, fmt.Errorf("decode Cert Spotter issuance %s: %w", r.ID, err)
		}
		is := Issuance{
			ID: r.ID, TBSSHA256: strings.ToLower(r.TBSSHA256), CertSHA256: strings.ToLower(r.CertSHA256),
			Names: normalizeNames(r.DNSNames), NotBefore: nb.UTC(), NotAfter: na.UTC(),
			Revoked: r.Revoked != nil && *r.Revoked,
		}
		if r.Issuer != nil {
			is.Issuer, is.IssuerDN = r.Issuer.FriendlyName, r.Issuer.Name
			for _, d := range r.Issuer.CAADomains {
				is.IssuerCAA = append(is.IssuerCAA, strings.ToLower(d))
			}
		}
		if r.CertDER != "" {
			if der, err := base64.StdEncoding.DecodeString(r.CertDER); err == nil {
				is.Serial = serialOf(der)
			}
		}
		out = append(out, is)
	}
	return out, nil
}

// serialOf returns the serial of a DER certificate or precertificate in the
// format of core.Certificate.Serial, or "" when it does not parse.
func serialOf(der []byte) string {
	c, err := x509.ParseCertificate(der)
	if err != nil {
		return ""
	}
	s := strings.TrimLeft(hex.EncodeToString(c.SerialNumber.Bytes()), "0")
	if s == "" {
		return "0"
	}
	return s
}

// normalizeNames lower-cases, sorts and de-duplicates DNS names. A name
// that does not normalize is kept as given in lower case: the inventory
// shows what the log holds.
func normalizeNames(in []string) []string {
	out := make([]string, 0, len(in))
	for _, n := range in {
		if v, err := names.Normalize(n); err == nil {
			n = v
		} else {
			n = strings.ToLower(strings.TrimSuffix(n, "."))
		}
		out = append(out, n)
	}
	slices.Sort(out)
	return slices.Compact(out)
}
