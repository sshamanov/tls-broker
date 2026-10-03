package dnsproxy

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/netip"
	"strings"
	"time"

	"tls-broker/internal/core"
	"tls-broker/internal/httpx"
	"tls-broker/internal/metrics"
	"tls-broker/internal/names"
)

const (
	// maxBody bounds every request body; a present request is ~150 bytes.
	maxBody = 4 << 10
	// maxValueLen is the longest TXT value accepted (one TXT string).
	maxValueLen = 255
)

// Audit reasons of cleanup, which involves no gate decision.
const (
	reasonOwner    = "owner"     // the caller presented the challenge
	reasonNotOwner = "not_owner" // another source address presented it
	// reasonNothing: a cleanup by fqdn and value found no active challenge
	// of the caller (already cleaned, never presented, or presented by
	// another source); it succeeds without touching DNS.
	reasonNothing = "nothing_to_clean"
)

// Options are the dependencies of a Handler.
type Options struct {
	Gate       core.Gate
	Engine     core.DNSEngine
	Challenges core.ChallengeStore
	Auditor    core.Auditor
	Metrics    metrics.Recorder // nil: metrics.Nop
	Clock      core.Clock       // nil: core.SystemClock
	Logger     *slog.Logger     // nil: slog.Default()
	Zones      names.Zones
	Config     core.DNSProxyConfig
}

// Handler serves the DNS proxy API.
type Handler struct {
	o   Options
	lim *limiter
	mux *http.ServeMux
}

// New builds a Handler.
func New(o Options) *Handler {
	if o.Metrics == nil {
		o.Metrics = metrics.Nop{}
	}
	if o.Clock == nil {
		o.Clock = core.SystemClock{}
	}
	if o.Logger == nil {
		o.Logger = slog.Default()
	}
	h := &Handler{o: o, lim: newLimiter(o.Config.MaxPerSource, o.Clock)}
	h.mux = http.NewServeMux()
	body := httpx.MaxBody(maxBody)
	h.mux.Handle("POST /dns/present", body(http.HandlerFunc(h.present)))
	h.mux.Handle("POST /dns/cleanup", body(http.HandlerFunc(h.cleanupBody)))
	h.mux.HandleFunc("DELETE /dns/challenges/{id}", h.cleanupPath)
	h.mux.HandleFunc("GET /dns/challenges", h.list)
	return h
}

// ServeHTTP implements http.Handler for the /dns/ routes.
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) { h.mux.ServeHTTP(w, r) }

// presentRequest names the identifier either directly or, in the form the
// stock acme.sh (dns_acmeproxy) and lego (httpreq) hooks send, as the
// challenge record's fqdn. Exactly one of Identifier and FQDN is set.
type presentRequest struct {
	Identifier string `json:"identifier,omitempty"`
	FQDN       string `json:"fqdn,omitempty"`
	Value      string `json:"value"`
}

type presentResponse struct {
	ChallengeID string `json:"challenge_id"`
	Record      string `json:"record"`
	Value       string `json:"value"`
}

// cleanupRequest is either {"challenge_id"} or {"fqdn","value"}.
type cleanupRequest struct {
	ChallengeID string `json:"challenge_id"`
	FQDN        string `json:"fqdn"`
	Value       string `json:"value"`
}

// cleanupResponse answers a cleanup by fqdn. Stock hooks treat the call as
// successful only when the body contains the value in double quotes.
type cleanupResponse struct {
	FQDN  string `json:"fqdn"`
	Value string `json:"value"`
}

type challengeView struct {
	ChallengeID string    `json:"challenge_id"`
	Record      string    `json:"record"`
	Value       string    `json:"value"`
	State       string    `json:"state"`
	CreatedAt   time.Time `json:"created_at"`
}

func decode(w http.ResponseWriter, r *http.Request, v any) bool {
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	err := dec.Decode(v)
	if err == nil {
		if _, e2 := dec.Token(); e2 != io.EOF {
			err = errors.New("trailing data")
		}
	}
	if err != nil {
		if httpx.IsBodyTooLarge(err) {
			httpx.WriteProblemStatus(w, http.StatusRequestEntityTooLarge, core.ProblemMalformed, "request body too large")
		} else {
			httpx.WriteProblemStatus(w, http.StatusBadRequest, core.ProblemMalformed, "request body must be a single JSON object with the documented fields")
		}
		return false
	}
	return true
}

// validValue accepts one printable ASCII TXT string of 1..255 characters
// without space, double quote or backslash (the engine publishes it quoted).
func validValue(v string) bool {
	if v == "" || len(v) > maxValueLen {
		return false
	}
	for i := 0; i < len(v); i++ {
		c := v[i]
		if c <= 0x20 || c >= 0x7f || c == '"' || c == '\\' {
			return false
		}
	}
	return true
}

func (h *Handler) audit(ctx context.Context, typ, src string, set []string, d core.Decision, result, detail, challengeID string) {
	dec := "deny"
	if d.Allowed {
		dec = "allow"
	}
	if detail == "" {
		detail = d.Detail
	}
	if challengeID != "" {
		if detail != "" {
			detail += " "
		}
		detail += "challenge=" + challengeID
	}
	h.o.Auditor.Record(ctx, core.AuditEvent{
		Type: typ, Mode: core.ModeDNSProxy, SourceIP: src, Names: set,
		Decision: dec, Reason: d.Reason, Result: result, GrantID: d.GrantID, Detail: detail,
	})
}

// source returns the caller's IPv4 or writes the not_ipv4 denial.
func (h *Handler) source(w http.ResponseWriter, r *http.Request, typ string, set []string) (netip.Addr, bool) {
	src, ok := httpx.SourceIP(r.Context())
	if ok {
		return src, true
	}
	d := core.Decision{Reason: core.ReasonNotIPv4}
	h.o.Metrics.GateDecision(core.ModeDNSProxy, false, d.Reason)
	h.o.Metrics.Request(core.ModeDNSProxy, metrics.OutcomeDenied)
	h.audit(r.Context(), typ, "", set, d, "denied", "", "")
	httpx.WriteProblem(w, core.NewProblem(core.ProblemUnauthorized, "denied: %s (the source address is not a usable IPv4 address)", d.Reason))
	return netip.Addr{}, false
}

// identFromFQDN returns the identifier whose challenge record fqdn is:
// "_acme-challenge.foo.example.com." gives "foo.example.com". The record of
// "*.N" is the record of "N", so the result is never a wildcard.
func identFromFQDN(fqdn string) (string, error) {
	name, ok := names.IdentifierFromChallengeRecord(strings.TrimSpace(fqdn))
	if !ok {
		return "", core.NewProblem(core.ProblemMalformed, "fqdn must be _acme-challenge.<name>").WithStatus(http.StatusBadRequest)
	}
	ident, err := names.Normalize(name)
	if err != nil {
		return "", err
	}
	if names.IsWildcard(ident) {
		return "", core.NewProblem(core.ProblemMalformed, "fqdn must not contain a wildcard label").WithStatus(http.StatusBadRequest)
	}
	return ident, nil
}

func (h *Handler) present(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var req presentRequest
	if !decode(w, r, &req) {
		h.o.Metrics.Request(core.ModeDNSProxy, metrics.OutcomeError)
		return
	}
	var ident string
	var err error
	switch {
	case req.Identifier != "" && req.FQDN != "":
		err = core.NewProblem(core.ProblemMalformed, "give either identifier or fqdn, not both").WithStatus(http.StatusBadRequest)
	case req.FQDN != "":
		ident, err = identFromFQDN(req.FQDN)
	default:
		ident, err = names.Normalize(req.Identifier)
	}
	if err != nil {
		h.o.Metrics.Request(core.ModeDNSProxy, metrics.OutcomeError)
		httpx.WriteError(w, err)
		return
	}
	src, ok := h.source(w, r, core.AuditDNSPresent, []string{ident})
	if !ok {
		return
	}
	set, err := names.NewSet(ident)
	if err != nil {
		h.o.Metrics.Request(core.ModeDNSProxy, metrics.OutcomeError)
		httpx.WriteError(w, err)
		return
	}
	if !h.o.Zones.Contains(names.Base(ident)) {
		d := core.Decision{Reason: core.ReasonOutsideManagedZone}
		h.o.Metrics.Request(core.ModeDNSProxy, metrics.OutcomeDenied)
		h.audit(ctx, core.AuditDNSPresent, src.String(), set.Names(), d, "denied", "", "")
		httpx.WriteProblem(w, core.NewProblem(core.ProblemRejectedIdentifier,
			"%s is outside the zones managed by this broker", ident).WithStatus(http.StatusNotFound))
		return
	}
	if !validValue(req.Value) {
		h.o.Metrics.Request(core.ModeDNSProxy, metrics.OutcomeError)
		httpx.WriteProblemStatus(w, http.StatusBadRequest, core.ProblemMalformed,
			"value must be 1 to 255 printable ASCII characters without spaces, quotes or backslashes")
		return
	}

	dec, err := h.o.Gate.Authorize(ctx, core.ModeDNSProxy, src, set)
	if err != nil {
		h.o.Logger.Warn("dnsproxy: gate failed", "source", src, "err", err)
		h.o.Metrics.Request(core.ModeDNSProxy, metrics.OutcomeUnavailable)
		h.audit(ctx, core.AuditDNSPresent, src.String(), set.Names(), core.Decision{}, "failed", "gate unavailable", "")
		httpx.WriteProblem(w, core.NewProblem(core.ProblemServerInternal, "authorization could not be decided, try again").
			WithStatus(http.StatusServiceUnavailable).WithRetryAfter(5*time.Second))
		return
	}
	h.o.Metrics.GateDecision(core.ModeDNSProxy, dec.Allowed, dec.Reason)
	if !dec.Allowed {
		h.o.Metrics.Request(core.ModeDNSProxy, metrics.OutcomeDenied)
		h.audit(ctx, core.AuditDNSPresent, src.String(), set.Names(), dec, "denied", "", "")
		detail := "denied: " + dec.Reason
		if dec.Name != "" {
			detail += " (" + dec.Name + ")"
		}
		httpx.WriteProblem(w, core.NewProblem(core.ProblemUnauthorized, "%s", detail))
		return
	}

	record := names.ChallengeRecord(ident)
	owner := core.DNSProxyOwner(src)
	// A repeat of an existing present is idempotent and costs nothing, so it
	// does not count against the limiter.
	if _, err := h.o.Challenges.FindActive(ctx, owner, record, req.Value); errors.Is(err, core.ErrNotFound) {
		if ok, wait := h.lim.allow(src); !ok {
			h.o.Metrics.Request(core.ModeDNSProxy, metrics.OutcomeRateLimited)
			h.audit(ctx, core.AuditDNSPresent, src.String(), set.Names(),
				core.Decision{Reason: core.ReasonRateLimited, GrantID: dec.GrantID}, "denied", "per-source limit reached", "")
			httpx.WriteProblem(w, core.NewProblem(core.ProblemRateLimited,
				"too many challenges from this source address, retry later").WithRetryAfter(wait))
			return
		}
	} else if err != nil {
		h.o.Logger.Warn("dnsproxy: challenge lookup failed", "err", err)
	}

	pctx := ctx
	if t := h.o.Config.PresentTimeout; t > 0 {
		var cancel context.CancelFunc
		pctx, cancel = context.WithTimeout(ctx, t)
		defer cancel()
	}
	id, err := h.o.Engine.Present(pctx, owner, record, req.Value)
	if err != nil {
		h.presentFailed(w, r, src, set, dec, err)
		return
	}
	h.o.Metrics.Request(core.ModeDNSProxy, metrics.OutcomeOK)
	h.audit(ctx, core.AuditDNSPresent, src.String(), set.Names(), dec, "ok", "", id)
	httpx.WriteJSON(w, http.StatusCreated, presentResponse{ChallengeID: id, Record: record, Value: req.Value})
}

func (h *Handler) presentFailed(w http.ResponseWriter, r *http.Request, src netip.Addr, set names.Set, dec core.Decision, err error) {
	var p *core.Problem
	outcome := metrics.OutcomeUnavailable
	switch {
	case errors.Is(err, core.ErrOutsideManagedZones):
		p = core.NewProblem(core.ProblemRejectedIdentifier, "identifier is outside the zones managed by this broker").
			WithStatus(http.StatusNotFound)
		outcome = metrics.OutcomeError
	case errors.Is(err, core.ErrDNSPropagation), errors.Is(err, context.DeadlineExceeded):
		p = core.NewProblem(core.ProblemServerInternal, "the TXT value did not become visible in public DNS in time").
			WithStatus(http.StatusGatewayTimeout)
	default:
		if r.Context().Err() == nil {
			h.o.Logger.Warn("dnsproxy: present failed", "source", src, "err", err)
		}
		p = core.NewProblem(core.ProblemServerInternal, "the DNS backend is temporarily unavailable").
			WithStatus(http.StatusServiceUnavailable).WithRetryAfter(10 * time.Second)
	}
	h.o.Metrics.Request(core.ModeDNSProxy, outcome)
	h.audit(r.Context(), core.AuditDNSPresent, src.String(), set.Names(), dec, "failed", "present failed: "+p.Detail, "")
	httpx.WriteProblem(w, p)
}

func (h *Handler) cleanupBody(w http.ResponseWriter, r *http.Request) {
	var req cleanupRequest
	if !decode(w, r, &req) {
		h.o.Metrics.Request(core.ModeDNSProxy, metrics.OutcomeError)
		return
	}
	if req.FQDN != "" || req.Value != "" {
		if req.ChallengeID != "" {
			h.o.Metrics.Request(core.ModeDNSProxy, metrics.OutcomeError)
			httpx.WriteProblemStatus(w, http.StatusBadRequest, core.ProblemMalformed, "give either challenge_id or fqdn and value, not both")
			return
		}
		h.cleanupValue(w, r, req.FQDN, req.Value)
		return
	}
	h.cleanup(w, r, strings.TrimSpace(req.ChallengeID))
}

// cleanupValue removes the caller's active challenges with the record of fqdn
// and that value. It is idempotent: when there is nothing to remove (already
// cleaned, never presented, or presented by another source, whose value is
// left alone) it still answers 200, so a retried client hook never fails.
func (h *Handler) cleanupValue(w http.ResponseWriter, r *http.Request, fqdn, value string) {
	ctx := r.Context()
	ident, err := identFromFQDN(fqdn)
	if err != nil {
		h.o.Metrics.Request(core.ModeDNSProxy, metrics.OutcomeError)
		httpx.WriteError(w, err)
		return
	}
	if !validValue(value) {
		h.o.Metrics.Request(core.ModeDNSProxy, metrics.OutcomeError)
		httpx.WriteProblemStatus(w, http.StatusBadRequest, core.ProblemMalformed,
			"value must be 1 to 255 printable ASCII characters without spaces, quotes or backslashes")
		return
	}
	set := []string{ident}
	src, ok := h.source(w, r, core.AuditDNSCleanup, set)
	if !ok {
		return
	}
	record := names.ChallengeRecord(ident)
	rows, err := h.o.Challenges.ListByOwner(ctx, core.DNSProxyOwner(src))
	if err != nil {
		h.unavailable(w, r, src, "", err)
		return
	}
	cleaned := 0
	for _, c := range rows {
		if c.RecordName != record || c.Value != value {
			continue
		}
		if err := h.o.Engine.Cleanup(ctx, c.ID); err != nil && !errors.Is(err, core.ErrNotFound) {
			h.unavailable(w, r, src, c.ID, err)
			return
		}
		cleaned++
		h.audit(ctx, core.AuditDNSCleanup, src.String(), set, core.Decision{Allowed: true, Reason: reasonOwner}, "ok", "", c.ID)
	}
	if cleaned == 0 {
		h.audit(ctx, core.AuditDNSCleanup, src.String(), set, core.Decision{Allowed: true, Reason: reasonNothing}, "ok",
			"no active challenge of this source with that value", "")
	}
	h.o.Metrics.Request(core.ModeDNSProxy, metrics.OutcomeOK)
	httpx.WriteJSON(w, http.StatusOK, cleanupResponse{FQDN: fqdn, Value: value})
}

func (h *Handler) cleanupPath(w http.ResponseWriter, r *http.Request) {
	h.cleanup(w, r, r.PathValue("id"))
}

func (h *Handler) cleanup(w http.ResponseWriter, r *http.Request, id string) {
	ctx := r.Context()
	if id == "" {
		h.o.Metrics.Request(core.ModeDNSProxy, metrics.OutcomeError)
		httpx.WriteProblemStatus(w, http.StatusBadRequest, core.ProblemMalformed, "challenge_id is required")
		return
	}
	src, ok := h.source(w, r, core.AuditDNSCleanup, nil)
	if !ok {
		return
	}
	ch, err := h.o.Challenges.Get(ctx, id)
	switch {
	case errors.Is(err, core.ErrNotFound):
		h.o.Metrics.Request(core.ModeDNSProxy, metrics.OutcomeError)
		h.audit(ctx, core.AuditDNSCleanup, src.String(), nil, core.Decision{}, "failed", "unknown challenge", id)
		httpx.WriteProblemStatus(w, http.StatusNotFound, core.ProblemMalformed, "unknown challenge")
		return
	case err != nil:
		h.unavailable(w, r, src, id, err)
		return
	}
	set := recordNames(ch.RecordName)
	if ch.Owner != core.DNSProxyOwner(src) {
		d := core.Decision{Reason: reasonNotOwner}
		h.o.Metrics.Request(core.ModeDNSProxy, metrics.OutcomeDenied)
		h.audit(ctx, core.AuditDNSCleanup, src.String(), set, d, "denied", "challenge belongs to another source", id)
		httpx.WriteProblem(w, core.NewProblem(core.ProblemUnauthorized, "denied: the challenge was presented by another source address"))
		return
	}
	allow := core.Decision{Allowed: true, Reason: reasonOwner}
	if err := h.o.Engine.Cleanup(ctx, id); err != nil {
		if errors.Is(err, core.ErrNotFound) {
			h.o.Metrics.Request(core.ModeDNSProxy, metrics.OutcomeError)
			httpx.WriteProblemStatus(w, http.StatusNotFound, core.ProblemMalformed, "unknown challenge")
			return
		}
		h.unavailable(w, r, src, id, err)
		return
	}
	h.o.Metrics.Request(core.ModeDNSProxy, metrics.OutcomeOK)
	h.audit(ctx, core.AuditDNSCleanup, src.String(), set, allow, "ok", "", id)
	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) unavailable(w http.ResponseWriter, r *http.Request, src netip.Addr, id string, err error) {
	h.o.Logger.Warn("dnsproxy: cleanup failed", "source", src, "challenge", id, "err", err)
	h.o.Metrics.Request(core.ModeDNSProxy, metrics.OutcomeUnavailable)
	h.audit(r.Context(), core.AuditDNSCleanup, src.String(), nil, core.Decision{}, "failed", "cleanup failed", id)
	httpx.WriteProblem(w, core.NewProblem(core.ProblemServerInternal, "the DNS backend is temporarily unavailable").
		WithStatus(http.StatusServiceUnavailable).WithRetryAfter(10*time.Second))
}

func (h *Handler) list(w http.ResponseWriter, r *http.Request) {
	src, ok := h.source(w, r, core.AuditDNSPresent, nil)
	if !ok {
		return
	}
	rows, err := h.o.Challenges.ListByOwner(r.Context(), core.DNSProxyOwner(src))
	if err != nil {
		h.unavailable(w, r, src, "", err)
		return
	}
	out := make([]challengeView, 0, len(rows))
	for _, c := range rows {
		out = append(out, challengeView{ChallengeID: c.ID, Record: c.RecordName, Value: c.Value, State: string(c.State), CreatedAt: c.CreatedAt})
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"challenges": out})
}

func recordNames(record string) []string {
	if id, ok := names.IdentifierFromChallengeRecord(record); ok {
		return []string{id}
	}
	return nil
}

// Sweep removes DNS-proxy challenges older than Config.ChallengeTTL that were
// never cleaned up. The app calls it periodically (for example every minute).
// Challenges of broker orders are left to their own flow. It returns how many
// challenges were cleaned and the first error after trying all of them.
func (h *Handler) Sweep(ctx context.Context) (int, error) {
	h.lim.gc()
	ttl := h.o.Config.ChallengeTTL
	if ttl <= 0 {
		return 0, nil
	}
	stale, err := h.o.Challenges.ListStale(ctx, h.o.Clock.Now().Add(-ttl))
	if err != nil {
		return 0, err
	}
	var first error
	n := 0
	for _, c := range stale {
		if !strings.HasPrefix(c.Owner, "dnsproxy:") {
			continue
		}
		src := strings.TrimPrefix(c.Owner, "dnsproxy:")
		d := core.Decision{Allowed: true}
		if err := h.o.Engine.Cleanup(ctx, c.ID); err != nil {
			if first == nil {
				first = err
			}
			h.o.Logger.Warn("dnsproxy: stale cleanup failed", "challenge", c.ID, "err", err)
			h.audit(ctx, core.AuditDNSCleanup, src, recordNames(c.RecordName), d, "failed", "stale sweep failed", c.ID)
			continue
		}
		n++
		h.audit(ctx, core.AuditDNSCleanup, src, recordNames(c.RecordName), d, "ok", "stale sweep after challenge_ttl", c.ID)
	}
	return n, first
}
