package acmesrv

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"

	"tls-broker/internal/core"
	"tls-broker/internal/core/coretest"
)

func (e *env) do(method, path string) *response {
	e.t.Helper()
	req, _ := http.NewRequest(method, e.url(path), nil)
	resp, err := e.httpClient().Do(req)
	if err != nil {
		e.t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return &response{Response: resp, body: b}
}

func checkCommonHeaders(t *testing.T, e *env, r *response) {
	t.Helper()
	if r.Header.Get("Replay-Nonce") == "" {
		t.Fatalf("%s: no Replay-Nonce", r.Request.URL)
	}
	if want := `<` + e.url(pathDirectory) + `>;rel="index"`; r.Header.Values("Link")[0] != want {
		t.Fatalf("%s: Link %v", r.Request.URL, r.Header.Values("Link"))
	}
}

func TestDirectory(t *testing.T) {
	e := newEnv(t, func(o *Options) { o.TermsOfService = "https://broker.test/tos" })
	r := e.do(http.MethodGet, pathDirectory)
	checkCommonHeaders(t, e, r)
	if r.StatusCode != http.StatusOK || r.Header.Get("Content-Type") != "application/json" {
		t.Fatalf("%d %q", r.StatusCode, r.Header.Get("Content-Type"))
	}
	var dir map[string]any
	if err := json.Unmarshal(r.body, &dir); err != nil {
		t.Fatal(err)
	}
	want := map[string]string{
		"newNonce": pathNewNonce, "newAccount": pathNewAccount, "newOrder": pathNewOrder,
		"keyChange": pathKeyChange, "renewalInfo": pathRenewalInfo,
	}
	for k, p := range want {
		if dir[k] != e.url(p) {
			t.Fatalf("%s = %v, want %s", k, dir[k], e.url(p))
		}
	}
	for _, absent := range []string{"revokeCert", "newAuthz"} {
		if _, ok := dir[absent]; ok {
			t.Fatalf("%s present", absent)
		}
	}
	meta := dir["meta"].(map[string]any)
	if meta["externalAccountRequired"] != false || meta["termsOfService"] != "https://broker.test/tos" {
		t.Fatalf("meta %v", meta)
	}
	if len(dir) != len(want)+1 {
		t.Fatalf("unexpected keys: %v", dir)
	}

	// Without terms of service, meta has none.
	e2 := newEnv(t)
	r = e2.do(http.MethodGet, pathDirectory)
	if strings.Contains(string(r.body), "termsOfService") {
		t.Fatalf("termsOfService present: %s", r.body)
	}
}

func TestNewNonce(t *testing.T) {
	e := newEnv(t)
	head := e.do(http.MethodHead, pathNewNonce)
	get := e.do(http.MethodGet, pathNewNonce)
	if head.StatusCode != http.StatusOK || get.StatusCode != http.StatusNoContent {
		t.Fatalf("HEAD %d GET %d", head.StatusCode, get.StatusCode)
	}
	for _, r := range []*response{head, get} {
		checkCommonHeaders(t, e, r)
		if r.Header.Get("Cache-Control") != "no-store" {
			t.Fatalf("Cache-Control %q", r.Header.Get("Cache-Control"))
		}
	}
	if head.Header.Get("Replay-Nonce") == get.Header.Get("Replay-Nonce") {
		t.Fatal("nonces repeat")
	}
	expectProblem(t, e.do(http.MethodPost, pathNewNonce), 405, core.ProblemMalformed)
}

func TestUnsupportedSurface(t *testing.T) {
	e := newEnv(t)
	c := e.newRaw(coretest.GenKey()).register()
	// revokeCert is not offered.
	r := c.post(e.url(pathRevokeCert), map[string]any{"certificate": "AAAA"})
	p := expectProblem(t, r, 403, core.ProblemUnauthorized)
	if !strings.Contains(p.Detail, "revocation is not offered") {
		t.Fatalf("detail %q", p.Detail)
	}
	checkCommonHeaders(t, e, r)
	// ACMEv1 and unknown paths.
	expectProblem(t, e.do(http.MethodPost, "/new-reg"), 404, core.ProblemMalformed)
	expectProblem(t, e.do(http.MethodGet, "/new-authz"), 404, core.ProblemMalformed)
	expectProblem(t, e.do(http.MethodPost, "/order/a/b/c"), 404, core.ProblemMalformed)
	// Plain GET on a resource: POST-as-GET is required.
	_, loc := c.newOrder("a.example.com")
	r = e.do(http.MethodGet, strings.TrimPrefix(loc, e.base))
	p = expectProblem(t, r, 405, core.ProblemMalformed)
	if r.Header.Get("Allow") != "POST" || !strings.Contains(p.Detail, "POST-as-GET") {
		t.Fatalf("Allow %q detail %q", r.Header.Get("Allow"), p.Detail)
	}
	// Outside the ACME prefix.
	resp, err := e.httpClient().Get(e.ts.URL + PathPrefix + "x/directory")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("outside prefix: %d", resp.StatusCode)
	}
}

// TestHeadersOnEveryResponse checks Replay-Nonce and the index link on
// success responses of every resource type.
func TestHeadersOnEveryResponse(t *testing.T) {
	e := newEnv(t)
	c := e.newRaw(coretest.GenKey())
	r := c.post(e.url(pathNewAccount), map[string]any{})
	checkCommonHeaders(t, e, r)
	c.kid = r.Header.Get("Location")
	o, loc := c.newOrder("a.example.com")
	for _, u := range []string{c.kid, loc, o.Authorizations[0]} {
		r := c.post(u, nil)
		if r.StatusCode != http.StatusOK {
			t.Fatalf("%s: %d", u, r.StatusCode)
		}
		checkCommonHeaders(t, e, r)
	}
	r = c.post(o.Finalize, csrPayload(coretest.MakeCSR(coretest.GenKey(), "a.example.com")))
	checkCommonHeaders(t, e, r)
	var fin orderObj
	_ = json.Unmarshal(r.body, &fin)
	checkCommonHeaders(t, e, c.post(fin.Certificate, nil))
}

// TestExternalURLWithPath: URLs follow the configured external URL, read per
// request, including a path prefix.
func TestExternalURLWithPath(t *testing.T) {
	e := newEnv(t)
	e.cfg.Update(func(c *core.Config) { c.Server.ExternalURL = "https://broker.example.com/" })
	r := e.do(http.MethodGet, pathDirectory)
	if !strings.Contains(string(r.body), `"newOrder":"https://broker.example.com/acme/new-order"`) {
		t.Fatalf("directory %s", r.body)
	}
	// A path prefix that the request does not carry: not found.
	e.cfg.Update(func(c *core.Config) { c.Server.ExternalURL = "https://broker.example.com/tls" })
	expectProblem(t, e.do(http.MethodGet, pathDirectory), 404, core.ProblemMalformed)
}
