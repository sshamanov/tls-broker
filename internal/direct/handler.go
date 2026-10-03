package direct

import (
	"archive/tar"
	"bytes"
	"context"
	"net/http"
	"strconv"
	"strings"
	"time"

	"tls-broker/internal/core"
	"tls-broker/internal/httpx"
	"tls-broker/internal/metrics"
)

// PathPrefix is where the direct API is mounted.
const PathPrefix = "/cert/"

// wildcardPathPrefix introduces the wildcard form: /cert/wildcard/<base>.
const wildcardPathPrefix = "wildcard/"

// IdentifierFromPath maps a request path to the requested identifier, not yet
// normalized: "/cert/foo.example.com" -> "foo.example.com",
// "/cert/wildcard/example.com" -> "*.example.com". A "*" in the path, an
// empty name or extra path segments give ok=false.
func IdentifierFromPath(path string) (identifier string, ok bool) {
	rest, found := strings.CutPrefix(path, PathPrefix)
	if !found {
		return "", false
	}
	wild := false
	if base, isWild := strings.CutPrefix(rest, wildcardPathPrefix); isWild {
		rest, wild = base, true
	}
	if rest == "" || strings.ContainsAny(rest, "/*") {
		return "", false
	}
	if wild {
		return "*." + rest, true
	}
	return rest, true
}

// Handler serves GET and HEAD on /cert/{name} and /cert/wildcard/{base}
// (architecture §24). The source address comes from httpx (RealIP
// middleware). A request waits at most DirectConfig.IssueTimeout (and never
// longer than its own context) for a synchronous issuance.
func (s *Service) Handler() http.Handler {
	return http.HandlerFunc(s.serveHTTP)
}

func (s *Service) serveHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD")
		httpx.WriteProblemStatus(w, http.StatusMethodNotAllowed, core.ProblemMalformed, "only GET and HEAD are supported")
		s.metrics.Request(core.ModeDirect, metrics.OutcomeError)
		return
	}
	raw, ok := IdentifierFromPath(r.URL.Path)
	if !ok {
		httpx.WriteProblem(w, notFound("use /cert/<name> or /cert/wildcard/<base>; \"*\" is not allowed in the path"))
		s.metrics.Request(core.ModeDirect, metrics.OutcomeError)
		return
	}
	cfg := s.cfg.Current()
	ctx := r.Context()
	if d := cfg.Direct.IssueTimeout; d > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, d)
		defer cancel()
	}
	src, _ := httpx.SourceIP(r.Context())
	c, err := s.Get(ctx, src, raw)
	if err != nil {
		if r.Context().Err() != nil {
			return // the client went away
		}
		p := core.AsProblem(err)
		if p == nil {
			p = core.ProblemFromError(err)
		}
		httpx.WriteProblem(w, p)
		s.metrics.Request(core.ModeDirect, outcomeOf(p.Status))
		return
	}
	s.metrics.Request(core.ModeDirect, metrics.OutcomeOK)

	h := w.Header()
	h.Set("Cache-Control", "no-store")
	h.Set("ETag", c.ETag())
	if etagMatches(r.Header.Get("If-None-Match"), c.ETag()) {
		w.WriteHeader(http.StatusNotModified)
		return
	}
	body, err := Tarball(c)
	if err != nil {
		h.Del("ETag")
		httpx.WriteError(w, err)
		return
	}
	h.Set("Content-Type", "application/x-tar")
	h.Set("Content-Disposition", `attachment; filename="`+DirName(c.Identifier)+`.tar"`)
	h.Set("Content-Length", strconv.Itoa(len(body)))
	w.WriteHeader(http.StatusOK)
	if r.Method == http.MethodGet {
		_, _ = w.Write(body)
	}
}

func outcomeOf(status int) metrics.Outcome {
	switch status {
	case http.StatusForbidden:
		return metrics.OutcomeDenied
	case http.StatusTooManyRequests:
		return metrics.OutcomeRateLimited
	case http.StatusServiceUnavailable:
		return metrics.OutcomeUnavailable
	}
	return metrics.OutcomeError
}

// etagMatches implements the weak comparison of If-None-Match (RFC 9110
// §13.1.2): "*" or any listed tag equal to etag, ignoring a W/ prefix.
func etagMatches(header, etag string) bool {
	if header == "" {
		return false
	}
	for _, t := range strings.Split(header, ",") {
		t = strings.TrimSpace(t)
		if t == "*" || strings.TrimPrefix(t, "W/") == etag {
			return true
		}
	}
	return false
}

// Tarball returns the response body: a ustar archive holding exactly
// privkey.pem (mode 0600) and fullchain.pem (mode 0644), in that order, owned
// by uid/gid 0, with the generation's write time as mtime.
func Tarball(c *Cert) ([]byte, error) {
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	for _, f := range []struct {
		name string
		mode int64
		data []byte
	}{{KeyFile, int64(keyMode), c.KeyPEM}, {ChainFile, int64(chainMode), c.ChainPEM}} {
		hdr := &tar.Header{
			Typeflag: tar.TypeReg, Name: f.name, Mode: f.mode, Size: int64(len(f.data)),
			ModTime: c.ModTime.UTC().Truncate(time.Second), Format: tar.FormatUSTAR,
		}
		if err := tw.WriteHeader(hdr); err != nil {
			return nil, err
		}
		if _, err := tw.Write(f.data); err != nil {
			return nil, err
		}
	}
	if err := tw.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}
