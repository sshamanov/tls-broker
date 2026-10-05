// Package confluence publishes pages to Confluence Server / Data Center
// through its REST API (/rest/api/content). It backs "tls-broker docs
// publish", which copies the user guide there; the broker itself never talks
// to Confluence.
//
// API is the port; Client implements it over HTTP with a personal access
// token ("Authorization: Bearer"), and confluencetest.Server is the fake.
// The token is held by the Client only: it never appears in errors or
// output.
package confluence

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// Page is a Confluence page as far as publishing needs it.
type Page struct {
	ID       string
	Title    string
	SpaceKey string
	Version  int
	Body     string // storage format; empty when not requested
}

// API is what the publisher needs from Confluence.
type API interface {
	// Page reads a page with its space, version and storage body.
	Page(ctx context.Context, id string) (*Page, error)
	// Children lists a page's direct child pages, in Confluence's order,
	// with versions (no bodies).
	Children(ctx context.Context, id string) ([]Page, error)
	// Update replaces a page's title and body; version is the new version
	// number (current + 1), message the version comment.
	Update(ctx context.Context, id, title, body string, version int, message string) (*Page, error)
	// Delete removes a page (Confluence moves it to the space's trash).
	Delete(ctx context.Context, id string) error
}

// Error is a non-success answer from Confluence.
type Error struct {
	Method string
	Path   string // without query
	Status int
	// Message is Confluence's own message, shortened.
	Message string
}

func (e *Error) Error() string {
	var hint string
	switch e.Status {
	case http.StatusUnauthorized:
		hint = "authentication failed: the access token is wrong, expired or revoked"
	case http.StatusForbidden:
		hint = "permission denied: the token's user may not do this"
	case http.StatusNotFound:
		hint = "not found, or not visible to the token's user"
	case http.StatusConflict:
		hint = "version conflict: the page changed meanwhile"
	}
	s := fmt.Sprintf("confluence: %s %s: %d %s", e.Method, e.Path, e.Status, http.StatusText(e.Status))
	if hint != "" {
		s += " (" + hint + ")"
	}
	if e.Message != "" {
		s += ": " + e.Message
	}
	return s
}

// StatusOf is the HTTP status of a Confluence error, 0 for any other error.
func StatusOf(err error) int {
	var e *Error
	if errors.As(err, &e) {
		return e.Status
	}
	return 0
}

// Client is the HTTP implementation of API.
type Client struct {
	base  string // without trailing "/"
	token string
	http  *http.Client
}

var _ API = (*Client)(nil)

// NewClient returns a client for the Confluence at baseURL (http or https,
// including any context path such as /confluence). hc nil uses a client
// with a 60 s timeout.
func NewClient(baseURL, token string, hc *http.Client) (*Client, error) {
	u, err := url.Parse(strings.TrimRight(baseURL, "/"))
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" || u.User != nil || u.RawQuery != "" {
		return nil, fmt.Errorf("confluence: base URL %q must be http(s)://host[/path]", baseURL)
	}
	if token == "" {
		return nil, errors.New("confluence: empty access token")
	}
	if hc == nil {
		hc = &http.Client{Timeout: 60 * time.Second}
	}
	return &Client{base: u.String(), token: token, http: hc}, nil
}

// maxMessage bounds the Confluence message kept in an Error.
const maxMessage = 300

func (c *Client) do(ctx context.Context, method, path string, query url.Values, in, out any) error {
	var body io.Reader
	if in != nil {
		b, err := json.Marshal(in)
		if err != nil {
			return err
		}
		body = bytes.NewReader(b)
	}
	u := c.base + path
	if len(query) > 0 {
		u += "?" + query.Encode()
	}
	req, err := http.NewRequestWithContext(ctx, method, u, body)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	req.Header.Set("Accept", "application/json")
	if in != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	// Confluence refuses state-changing requests without this (XSRF check).
	req.Header.Set("X-Atlassian-Token", "no-check")
	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("confluence: %s %s: %w", method, path, stripURL(err))
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 32<<20))
	if err != nil {
		return fmt.Errorf("confluence: %s %s: reading answer: %w", method, path, err)
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return &Error{Method: method, Path: path, Status: resp.StatusCode, Message: message(data)}
	}
	if out == nil {
		return nil
	}
	if err := json.Unmarshal(data, out); err != nil {
		return fmt.Errorf("confluence: %s %s: unexpected answer (%d bytes, not JSON as expected): %v", method, path, len(data), err)
	}
	return nil
}

// stripURL drops the request URL from a transport error (it is in the
// message already, as method and path).
func stripURL(err error) error {
	var ue *url.Error
	if errors.As(err, &ue) {
		return ue.Err
	}
	return err
}

// message is Confluence's error message from a JSON answer, or a short,
// single-line excerpt of anything else.
func message(data []byte) string {
	var m struct {
		Message string `json:"message"`
	}
	s := ""
	if json.Unmarshal(data, &m) == nil && m.Message != "" {
		s = m.Message
	} else if !bytes.Contains(data, []byte("<html")) && !bytes.Contains(data, []byte("<!DOCTYPE")) {
		s = string(data)
	}
	s = strings.Join(strings.Fields(s), " ")
	if len(s) > maxMessage {
		s = s[:maxMessage] + "…"
	}
	return s
}

type apiPage struct {
	ID    string `json:"id"`
	Type  string `json:"type"`
	Title string `json:"title"`
	Space *struct {
		Key string `json:"key"`
	} `json:"space,omitempty"`
	Version *struct {
		Number int `json:"number"`
	} `json:"version,omitempty"`
	Body *struct {
		Storage struct {
			Value string `json:"value"`
		} `json:"storage"`
	} `json:"body,omitempty"`
}

func (p apiPage) page() Page {
	out := Page{ID: p.ID, Title: p.Title}
	if p.Space != nil {
		out.SpaceKey = p.Space.Key
	}
	if p.Version != nil {
		out.Version = p.Version.Number
	}
	if p.Body != nil {
		out.Body = p.Body.Storage.Value
	}
	return out
}

func checkID(id string) error {
	if _, err := strconv.ParseUint(id, 10, 64); err != nil {
		return fmt.Errorf("confluence: page ID %q is not a number", id)
	}
	return nil
}

func contentPath(id string) string { return "/rest/api/content/" + id }

// Page implements API.
func (c *Client) Page(ctx context.Context, id string) (*Page, error) {
	if err := checkID(id); err != nil {
		return nil, err
	}
	var p apiPage
	if err := c.do(ctx, http.MethodGet, contentPath(id), url.Values{"expand": {"version,space,body.storage"}}, nil, &p); err != nil {
		return nil, err
	}
	out := p.page()
	return &out, nil
}

// childPageLimit is the page size for listing children.
const childPageLimit = 25

// Children implements API.
func (c *Client) Children(ctx context.Context, id string) ([]Page, error) {
	if err := checkID(id); err != nil {
		return nil, err
	}
	var out []Page
	for start := 0; ; {
		var r struct {
			Results []apiPage `json:"results"`
		}
		q := url.Values{"expand": {"version"}, "start": {strconv.Itoa(start)}, "limit": {strconv.Itoa(childPageLimit)}}
		if err := c.do(ctx, http.MethodGet, contentPath(id)+"/child/page", q, nil, &r); err != nil {
			return nil, err
		}
		for _, p := range r.Results {
			out = append(out, p.page())
		}
		if len(r.Results) < childPageLimit {
			return out, nil
		}
		start += len(r.Results)
	}
}

type storageBody struct {
	Storage struct {
		Value          string `json:"value"`
		Representation string `json:"representation"`
	} `json:"storage"`
}

func storage(body string) storageBody {
	var b storageBody
	b.Storage.Value, b.Storage.Representation = body, "storage"
	return b
}

// Update implements API.
func (c *Client) Update(ctx context.Context, id, title, body string, version int, msg string) (*Page, error) {
	if err := checkID(id); err != nil {
		return nil, err
	}
	type ver struct {
		Number  int    `json:"number"`
		Message string `json:"message,omitempty"`
	}
	in := struct {
		ID      string      `json:"id"`
		Type    string      `json:"type"`
		Title   string      `json:"title"`
		Version ver         `json:"version"`
		Body    storageBody `json:"body"`
	}{id, "page", title, ver{version, msg}, storage(body)}
	var p apiPage
	if err := c.do(ctx, http.MethodPut, contentPath(id), nil, in, &p); err != nil {
		return nil, err
	}
	out := p.page()
	return &out, nil
}

// Delete implements API (DELETE /rest/api/content/{id}).
func (c *Client) Delete(ctx context.Context, id string) error {
	if err := checkID(id); err != nil {
		return err
	}
	return c.do(ctx, http.MethodDelete, contentPath(id), nil, nil, nil)
}
