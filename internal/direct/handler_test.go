package direct

import (
	"archive/tar"
	"bytes"
	"encoding/json"
	"encoding/pem"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"tls-broker/internal/core"
	"tls-broker/internal/httpx"
)

func TestIdentifierFromPath(t *testing.T) {
	for path, want := range map[string]string{
		"/cert/foo.example.com":         "foo.example.com",
		"/cert/wildcard/example.com":    "*.example.com",
		"/cert/wildcard.example.com":    "wildcard.example.com",
		"/cert/*.example.com":           "",
		"/cert/wildcard/*.example.com":  "",
		"/cert/":                        "",
		"/cert/wildcard/":               "",
		"/cert/a/b.example.com":         "",
		"/cert/foo.example.com/":        "",
		"/other/foo.example.com":        "",
		"/cert/wildcard/a.example.com/": "",
	} {
		got, ok := IdentifierFromPath(path)
		if got != want || ok != (want != "") {
			t.Errorf("%s: %q %v, want %q", path, got, ok, want)
		}
	}
}

type httpEnv struct {
	*env
	h http.Handler
}

func newHTTPEnv(t *testing.T) *httpEnv {
	e := newEnv(t)
	res := httpx.NewResolver(httpx.Options{})
	return &httpEnv{env: e, h: httpx.RealIP(res)(e.svc.Handler())}
}

func (h *httpEnv) do(method, path string, hdr ...string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, "http://broker.test"+path, nil)
	req.RemoteAddr = device.String() + ":40000"
	for i := 0; i+1 < len(hdr); i += 2 {
		req.Header.Set(hdr[i], hdr[i+1])
	}
	w := httptest.NewRecorder()
	h.h.ServeHTTP(w, req)
	h.idle()
	return w
}

type tarEntry struct {
	hdr  *tar.Header
	data []byte
}

func readTar(t *testing.T, b []byte) []tarEntry {
	t.Helper()
	tr := tar.NewReader(bytes.NewReader(b))
	var out []tarEntry
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			return out
		}
		if err != nil {
			t.Fatal(err)
		}
		data, err := io.ReadAll(tr)
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, tarEntry{hdr, data})
	}
}

func TestHandlerServesTar(t *testing.T) {
	h := newHTTPEnv(t)
	w := h.do(http.MethodGet, "/cert/"+host)
	if w.Code != http.StatusOK {
		t.Fatalf("status %d: %s", w.Code, w.Body)
	}
	for k, v := range map[string]string{
		"Content-Type":        "application/x-tar",
		"Cache-Control":       "no-store",
		"Content-Disposition": `attachment; filename="dev.example.com.tar"`,
	} {
		if got := w.Header().Get(k); got != v {
			t.Errorf("%s = %q, want %q", k, got, v)
		}
	}
	if w.Header().Get("ETag") == "" || w.Header().Get("Content-Length") == "" {
		t.Fatal("missing ETag or Content-Length")
	}

	ents := readTar(t, w.Body.Bytes())
	if len(ents) != 2 || ents[0].hdr.Name != KeyFile || ents[1].hdr.Name != ChainFile {
		t.Fatalf("tar entries %d", len(ents))
	}
	gen := filepath.Join(h.dataDir, "certs", host, "generations", "000001")
	genTime := h.clock.Now().Truncate(time.Second)
	for i, want := range []struct {
		mode    int64
		pemType string
	}{{0o600, "RSA PRIVATE KEY"}, {0o644, "CERTIFICATE"}} {
		e := ents[i]
		if e.hdr.Mode != want.mode || e.hdr.Typeflag != tar.TypeReg || !e.hdr.ModTime.Equal(genTime) || e.hdr.Uid != 0 {
			t.Errorf("%s header %+v", e.hdr.Name, e.hdr)
		}
		disk, _ := os.ReadFile(filepath.Join(gen, e.hdr.Name))
		if !bytes.Equal(disk, e.data) {
			t.Errorf("%s differs from the file on disk", e.hdr.Name)
		}
		b, _ := pem.Decode(e.data)
		if b == nil || b.Type != want.pemType {
			t.Errorf("%s is not %s PEM", e.hdr.Name, want.pemType)
		}
	}
	// Byte-exact: the body is exactly what Tarball builds from the cache.
	c := h.mustGet(host)
	want, _ := Tarball(c)
	if !bytes.Equal(want, w.Body.Bytes()) {
		t.Fatal("body is not the canonical tarball")
	}

	// The one-liner works with the system tar (curl -sf ... | tar -x -C dir).
	tarBin, err := exec.LookPath("tar")
	if err != nil {
		t.Skip("no tar binary in this environment")
	}
	dir := t.TempDir()
	cmd := exec.Command(tarBin, "-x", "-C", dir)
	cmd.Stdin = bytes.NewReader(w.Body.Bytes())
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("tar -x: %v: %s", err, out)
	}
	for name, mode := range map[string]os.FileMode{KeyFile: 0o600, ChainFile: 0o644} {
		st, err := os.Stat(filepath.Join(dir, name))
		if err != nil {
			t.Fatal(err)
		}
		if st.Mode().Perm()&mode != st.Mode().Perm() || !st.ModTime().Equal(genTime) {
			t.Errorf("extracted %s: mode %v mtime %v", name, st.Mode().Perm(), st.ModTime())
		}
	}
}

func TestHandlerETagAndHead(t *testing.T) {
	h := newHTTPEnv(t)
	first := h.do(http.MethodGet, "/cert/"+host)
	etag := first.Header().Get("ETag")

	w := h.do(http.MethodGet, "/cert/"+host, "If-None-Match", etag)
	if w.Code != http.StatusNotModified || w.Body.Len() != 0 || w.Header().Get("ETag") != etag {
		t.Fatalf("conditional GET: %d, %d bytes", w.Code, w.Body.Len())
	}
	if w := h.do(http.MethodGet, "/cert/"+host, "If-None-Match", `"0-0", W/`+etag); w.Code != http.StatusNotModified {
		t.Fatalf("list/weak match: %d", w.Code)
	}
	if w := h.do(http.MethodGet, "/cert/"+host, "If-None-Match", `"1-other"`); w.Code != http.StatusOK {
		t.Fatalf("stale ETag: %d", w.Code)
	}
	w = h.do(http.MethodHead, "/cert/"+host)
	if w.Code != http.StatusOK || w.Body.Len() != 0 || w.Header().Get("Content-Length") != first.Header().Get("Content-Length") {
		t.Fatalf("HEAD: %d, %d bytes", w.Code, w.Body.Len())
	}
	// Polling with the ETag still counts as a fetch and drives renewal.
	h.clock.Advance(61 * day)
	w = h.do(http.MethodGet, "/cert/"+host, "If-None-Match", etag)
	if w.Code != http.StatusNotModified {
		t.Fatalf("poll before renewal finished: %d", w.Code)
	}
	h.wantCalls(2)
	w = h.do(http.MethodGet, "/cert/"+host, "If-None-Match", etag)
	if w.Code != http.StatusOK || w.Header().Get("ETag") == etag {
		t.Fatalf("after renewal: %d %s", w.Code, w.Header().Get("ETag"))
	}
	if w := h.do(http.MethodPost, "/cert/"+host); w.Code != http.StatusMethodNotAllowed || w.Header().Get("Allow") != "GET, HEAD" {
		t.Fatalf("POST: %d", w.Code)
	}
}

func TestHandlerWildcard(t *testing.T) {
	h := newHTTPEnv(t)
	w := h.do(http.MethodGet, "/cert/wildcard/example.com")
	if w.Code != http.StatusOK || w.Header().Get("Content-Disposition") != `attachment; filename="_wildcard.example.com.tar"` {
		t.Fatalf("%d %s", w.Code, w.Header().Get("Content-Disposition"))
	}
	if id := h.iss.Calls()[0].Identifier; id != "*.example.com" {
		t.Fatalf("issued %q", id)
	}
	if w := h.do(http.MethodGet, "/cert/*.example.com"); w.Code != http.StatusNotFound {
		t.Fatalf("star in path: %d", w.Code)
	}
}

func problemOf(t *testing.T, w *httptest.ResponseRecorder) core.Problem {
	t.Helper()
	if ct := w.Header().Get("Content-Type"); ct != core.ProblemContentType {
		t.Fatalf("content type %q", ct)
	}
	var p core.Problem
	if err := json.Unmarshal(w.Body.Bytes(), &p); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestHandlerErrors(t *testing.T) {
	h := newHTTPEnv(t)
	if w := h.do(http.MethodGet, "/cert/x.other.net"); w.Code != http.StatusNotFound || problemOf(t, w).Status != 404 {
		t.Fatalf("outside zone: %d", w.Code)
	}
	h.gate.Decide(core.Decision{Reason: core.ReasonWildcardGrantRequired})
	if w := h.do(http.MethodGet, "/cert/wildcard/example.com"); w.Code != http.StatusForbidden ||
		problemOf(t, w).Type != core.ProblemUnauthorized {
		t.Fatalf("denied: %d", w.Code)
	}
	h.gate.DecideFunc(nil)
	h.iss.set(func(f *fakeIssuer) {
		f.errs = []error{&core.ProviderError{Kind: core.ProviderRateLimited, RetryAfter: 3 * time.Hour}}
	})
	w := h.do(http.MethodGet, "/cert/"+host)
	if w.Code != http.StatusTooManyRequests || w.Header().Get("Retry-After") != "10800" ||
		problemOf(t, w).Type != core.ProblemRateLimited {
		t.Fatalf("rate limited: %d %q", w.Code, w.Header().Get("Retry-After"))
	}
	h.iss.set(func(f *fakeIssuer) { f.failAll = &core.ProviderError{Kind: core.ProviderDown} })
	w = h.do(http.MethodGet, "/cert/a.example.org")
	if w.Code != http.StatusServiceUnavailable || w.Header().Get("Retry-After") != "60" {
		t.Fatalf("down: %d %q", w.Code, w.Header().Get("Retry-After"))
	}
}

func TestHandlerHoldIsBounded(t *testing.T) {
	h := newHTTPEnv(t)
	h.cfg.Update(func(c *core.Config) {
		d := c.Direct
		d.IssueTimeout = 100 * time.Millisecond
		c.Direct = d
	})
	release := make(chan struct{})
	h.iss.set(func(f *fakeIssuer) { f.block = release })
	req := httptest.NewRequest(http.MethodGet, "http://broker.test/cert/"+host, nil)
	req.RemoteAddr = device.String() + ":40000"
	w := httptest.NewRecorder()
	h.h.ServeHTTP(w, req)
	if w.Code != http.StatusServiceUnavailable || w.Header().Get("Retry-After") == "" {
		t.Fatalf("held request: %d", w.Code)
	}
	// The job keeps running and its certificate is served next time.
	close(release)
	h.idle()
	if w := h.do(http.MethodGet, "/cert/"+host); w.Code != http.StatusOK {
		t.Fatalf("after issuance: %d", w.Code)
	}
	h.wantCalls(1)
}
