package ui

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"sync"
	"time"

	"net/http"

	"tls-broker/internal/auth"
	"tls-broker/internal/core"
)

const (
	probeTimeout = 8 * time.Second
	countCap     = 10000
)

type dashboardData struct {
	Snapshot core.SchedulerSnapshot
	CAs      []caStatus
	Queue    queueStatus
	Headroom []providerHeadroom
	Recent   []core.AuditEvent
	Expiring []expiringCert
	// Admin only.
	Counts   dashCounts
	Warnings []string
	Zones    []zoneView
	Accounts []accountView
	Config   *core.Config
}

type dashCounts struct {
	ACMECerts  string
	Direct     int
	DirectLive int
}

type zoneView struct {
	Zone    core.ZoneConfig
	Hosted  ZoneStatus // hosted zone in effect (configured or discovered)
	Status  core.CAAStatus
	Err     string
	Suggest []string // CAA records the operator can add
}

type accountView struct {
	Provider string
	URL      string
	Err      string
	Honoured bool
	Issuers  []string
}

// caStatus is one certificate authority in one word: operational, degraded
// (admitting, but its last answers were errors or rate limits) or
// unavailable (admission closed until RetryAt).
type caStatus struct {
	Name    string
	State   string
	RetryAt time.Time
	// Detail for admins.
	Snap core.ProviderSnapshot
}

// queueStatus is the issuance queue over all providers.
type queueStatus struct {
	InFlight   string // orders not yet finished (capped count)
	Waiting    int    // requests waiting for an admission slot
	SlotsInUse int
	SlotsTotal int
}

// providerHeadroom holds the rate-limit gauges of one provider.
type providerHeadroom struct {
	Provider string
	Gauges   []gauge
}

// gauge is one rate budget: how much of it is used, and its level.
type gauge struct {
	Label       string
	Key         string
	Used, Limit int
	RenewalOnly int
	Window      time.Duration
	Pct         int    // used share, 0..100
	Level       string // ok | caution | exhausted
}

// cautionPct is the used share from which a budget is shown as caution.
const cautionPct = 75

func newGauge(b core.BudgetUsage) gauge {
	g := gauge{Key: b.Key, Used: b.Used, Limit: b.Limit, RenewalOnly: b.RenewalOnly, Window: b.Window, Pct: pct(b.Used, b.Limit), Level: "ok"}
	switch b.Kind {
	case core.BudgetNewOrder:
		g.Label = "New orders"
	case core.BudgetCertDomain:
		g.Label = "Certificates for " + b.Key
	case core.BudgetCertSet:
		g.Label = "Renewals of " + b.Key
	default:
		g.Label = string(b.Kind)
	}
	switch {
	case budgetExhausted(b):
		g.Level = "exhausted"
	case g.Pct >= cautionPct:
		g.Level = "caution"
	}
	return g
}

// headroom keeps, per provider, the new-order budget and the most used
// per-domain and per-set budget: the ones that would refuse a request first.
// With all set (admins) every bucket is kept, most used first.
func headroom(snap core.SchedulerSnapshot, enabled map[string]bool, all bool) []providerHeadroom {
	var out []providerHeadroom
	for _, ps := range snap.Providers {
		if !enabled[ps.Name] {
			continue
		}
		ph := providerHeadroom{Provider: ps.Name}
		if all {
			ph.Gauges = allGauges(ps.Budgets)
			out = append(out, ph)
			continue
		}
		best := map[core.BudgetKind]core.BudgetUsage{}
		for _, b := range ps.Budgets {
			if cur, ok := best[b.Kind]; !ok || pct(b.Used, b.Limit) > pct(cur.Used, cur.Limit) {
				best[b.Kind] = b
			}
		}
		for _, k := range []core.BudgetKind{core.BudgetNewOrder, core.BudgetCertDomain, core.BudgetCertSet} {
			if b, ok := best[k]; ok {
				ph.Gauges = append(ph.Gauges, newGauge(b))
			}
		}
		out = append(out, ph)
	}
	return out
}

// allGauges is every budget as a gauge: the new-order budget first, then
// the others by used share, most used first.
func allGauges(budgets []core.BudgetUsage) []gauge {
	var out []gauge
	for _, b := range budgets {
		out = append(out, newGauge(b))
	}
	slices.SortStableFunc(out, func(a, b gauge) int {
		an, bn := a.Label == "New orders", b.Label == "New orders"
		switch {
		case an != bn && an:
			return -1
		case an != bn:
			return 1
		}
		return b.Pct - a.Pct
	})
	return out
}

func caStatuses(snap core.SchedulerSnapshot, enabled map[string]bool) []caStatus {
	var out []caStatus
	for _, ps := range snap.Providers {
		if !enabled[ps.Name] {
			continue
		}
		cs := caStatus{Name: ps.Name, State: "operational", Snap: ps}
		switch {
		case !ps.Open:
			cs.State, cs.RetryAt = "unavailable", ps.State.RetryAfter
		case ps.State.Health != core.ProviderHealthy && ps.State.Health != "", ps.State.Failures > 0:
			cs.State = "degraded"
		}
		out = append(out, cs)
	}
	return out
}

// recentLimit is how many issuance operations the status page lists.
const recentLimit = 8

// recentOperations keeps the events that are an outcome: certificates
// issued or failed, orders refused or ended, requests denied, DNS proxy
// publications. Allowed gate decisions and admitted orders are steps on the
// way and are left out.
func recentOperations(evs []core.AuditEvent) []core.AuditEvent {
	var out []core.AuditEvent
	for _, ev := range evs {
		o := outcome(ev)
		keep := false
		switch ev.Type {
		case core.AuditIssue, core.AuditDNSPresent:
			keep = true
		case core.AuditGate, core.AuditOrder:
			keep = o != core.AuditResultOK
		}
		if keep {
			out = append(out, ev)
		}
		if len(out) == recentLimit {
			break
		}
	}
	return out
}

// expiringLimit is how many certificates "Expiring next" lists.
const expiringLimit = 6

type expiringCert struct {
	Names    []string
	Mode     core.Mode
	Provider string
	NotAfter time.Time
	Life     lifetime
}

// lifetime places now and the renewal point on a certificate's validity, as
// percentages of it, for the lifetime bar.
type lifetime struct {
	NotBefore, NotAfter, RenewAt time.Time
	// RenewExpected: RenewAt is the usual point (two thirds of the
	// lifetime), not a schedule the broker keeps (direct cache).
	RenewExpected bool
	NowPct        int
	RenewPct      int
	State         string // ok | due | expired
}

func newLifetime(now, nb, na, renewAt time.Time) lifetime {
	l := lifetime{NotBefore: nb, NotAfter: na, RenewAt: renewAt, State: "ok"}
	total := na.Sub(nb)
	if total <= 0 {
		l.State = "expired"
		return l
	}
	if renewAt.IsZero() {
		l.RenewAt, l.RenewExpected = nb.Add(total*2/3), true
	}
	at := func(t time.Time) int {
		return int(min(max(t.Sub(nb)*100/total, 0), 100))
	}
	l.NowPct, l.RenewPct = at(now), at(l.RenewAt)
	switch {
	case !now.Before(na):
		l.State = "expired"
	case !now.Before(l.RenewAt):
		l.State = "due"
	}
	return l
}

// expiringNext returns the current certificate of each identifier set and
// mode that expires soonest.
func expiringNext(certs []core.Certificate, renewAt map[string]time.Time, now time.Time) []expiringCert {
	latest := map[string]core.Certificate{}
	for _, c := range certs {
		k := string(c.Mode) + " " + c.Names.Key()
		if cur, ok := latest[k]; !ok || c.NotAfter.After(cur.NotAfter) {
			latest[k] = c
		}
	}
	list := make([]core.Certificate, 0, len(latest))
	for _, c := range latest {
		list = append(list, c)
	}
	slices.SortFunc(list, func(a, b core.Certificate) int { return a.NotAfter.Compare(b.NotAfter) })
	var out []expiringCert
	for _, c := range list[:min(len(list), expiringLimit)] {
		out = append(out, expiringCert{Names: c.Names.Names(), Mode: c.Mode, Provider: c.Provider, NotAfter: c.NotAfter,
			Life: newLifetime(now, c.NotBefore, c.NotAfter, renewAt[c.ID])})
	}
	return out
}

func capped(n int) string {
	if n >= countCap {
		return fmt.Sprintf("%d+", countCap)
	}
	return fmt.Sprint(n)
}

func (h *Handler) dashboard(w http.ResponseWriter, r *http.Request, cur *auth.Current) {
	d := &dashboardData{Snapshot: h.Scheduler.Snapshot(), Config: h.Config.Current()}
	p := h.newPage(w, r, cur, "Broker status", "dashboard", d)
	if cur.User.Blocked {
		h.render(w, http.StatusOK, "dashboard", p)
		return
	}
	ctx := r.Context()
	now := h.Clock.Now()

	enabled := map[string]bool{}
	for _, pc := range d.Config.EnabledProviders() {
		enabled[pc.Name] = true
	}
	d.CAs = caStatuses(d.Snapshot, enabled)
	d.Headroom = headroom(d.Snapshot, enabled, p.Admin)
	for _, ps := range d.Snapshot.Providers {
		d.Queue.Waiting += ps.Waiting
		d.Queue.SlotsInUse += ps.SlotsInUse
		d.Queue.SlotsTotal += ps.SlotsTotal
	}
	active, err := h.Orders.ListActive(ctx)
	if err != nil {
		h.serverError(w, r, cur, "list orders", err)
		return
	}
	d.Queue.InFlight = capped(len(active))

	certs, err := h.Certs.List(ctx, core.CertificateFilter{ValidAt: now, Limit: countCap})
	if err != nil {
		h.serverError(w, r, cur, "list certificates", err)
		return
	}
	entries, err := h.Direct.List(ctx)
	if err != nil {
		h.serverError(w, r, cur, "list direct entries", err)
		return
	}
	renewAt := map[string]time.Time{}
	for _, e := range entries {
		if e.CertificateID != "" {
			renewAt[e.CertificateID] = e.RenewAt
		}
		if e.NotAfter.After(now) {
			d.Counts.DirectLive++
		}
	}
	d.Expiring = expiringNext(certs, renewAt, now)
	if evs, err := h.Audit.Query(ctx, activityQuery(core.AuditQuery{Types: activityTypes, Limit: 50}, p.Admin)); err != nil {
		h.Logger.Warn("ui: audit query failed", "error", err)
		p.Flash = firstFlash(p.Flash, &flash{Kind: "error", Text: "The activity log could not be read."})
	} else {
		d.Recent = recentOperations(evs)
	}

	if p.Admin {
		acme := 0
		for _, c := range certs {
			if c.Mode == core.ModeACME {
				acme++
			}
		}
		d.Counts.ACMECerts = capped(acme)
		d.Counts.Direct = len(entries)
		h.adminDashboard(ctx, d)
	}
	h.render(w, http.StatusOK, "dashboard", p)
}

func firstFlash(a, b *flash) *flash {
	if a != nil {
		return a
	}
	return b
}

// adminDashboard fills the admin-only parts: account URLs, zone CAA status
// and the warnings list. Network probes run in parallel under a timeout.
func (h *Handler) adminDashboard(ctx context.Context, d *dashboardData) {
	cfg := d.Config
	pctx, cancel := context.WithTimeout(ctx, probeTimeout)
	defer cancel()

	providers := h.Providers.Enabled()
	d.Accounts = make([]accountView, len(providers))
	d.Zones = make([]zoneView, len(cfg.Zones))
	var wg sync.WaitGroup
	for i, pr := range providers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			av := accountView{Provider: pr.Name()}
			if pc, ok := cfg.Provider(pr.Name()); ok {
				av.Honoured, av.Issuers = pc.AccountURIHonoured, pc.CAAIssuers
			}
			if u, err := pr.AccountURL(pctx); err != nil {
				av.Err = "account URL unavailable: " + err.Error()
			} else {
				av.URL = u
			}
			d.Accounts[i] = av
		}()
	}
	hosted := h.zoneStatuses(cfg)
	for i, z := range cfg.Zones {
		wg.Add(1)
		go func() {
			defer wg.Done()
			zv := zoneView{Zone: z, Hosted: hosted[z.Name]}
			if st, err := h.CAA.CheckCAA(pctx, z.Name); err != nil {
				zv.Err = err.Error()
			} else {
				zv.Status = st
			}
			d.Zones[i] = zv
		}()
	}
	wg.Wait()
	for i := range d.Zones {
		d.Zones[i].Suggest = suggestCAA(d.Zones[i].Zone.Name, d.Accounts)
	}
	d.Warnings = h.warnings(ctx, d)
}

// zoneStatuses returns the hosted zone in effect for each zone of cfg by
// name: what Deps.Zones reports, or the configured ID when there is no
// source (or it does not know the zone yet).
func (h *Handler) zoneStatuses(cfg *core.Config) map[string]ZoneStatus {
	out := make(map[string]ZoneStatus, len(cfg.Zones))
	for _, z := range cfg.Zones {
		st := ZoneStatus{Name: z.Name, HostedZoneID: z.HostedZoneID}
		if st.HostedZoneID == "" {
			st.Err = "hosted zone not discovered yet"
		}
		out[z.Name] = st
	}
	if h.Zones == nil {
		return out
	}
	for _, st := range h.Zones.ZoneStatuses() {
		if _, ok := out[st.Name]; ok {
			out[st.Name] = st
		}
	}
	return out
}

// suggestCAA builds CAA records for a zone that keep wildcards to pinned
// accounts: an unpinned issue record per CA (ordinary names may come from
// any of them, including the operator's own clients; the DNS-proxy condition
// of architecture §3.2 only judges issuewild when there is one), one
// issuewild record pinned with accounturi to the broker's account at each
// CA, and a reminder that every other ACME account needing wildcards gets an
// issuewild line of its own.
func suggestCAA(zone string, accounts []accountView) []string {
	var issue, wild []string
	for _, a := range accounts {
		if a.URL == "" || len(a.Issuers) == 0 {
			continue
		}
		if r := fmt.Sprintf(`%s. CAA 0 issue "%s"`, zone, a.Issuers[0]); !slices.Contains(issue, r) {
			issue = append(issue, r)
		}
		wild = append(wild, fmt.Sprintf(`%s. CAA 0 issuewild "%s; accounturi=%s"`, zone, a.Issuers[0], a.URL))
	}
	if len(wild) == 0 {
		return nil
	}
	wild = append(wild, "; add one issuewild line like the above, with its own accounturi, for each ACME account of yours that needs wildcards")
	return append(issue, wild...)
}

func (h *Handler) warnings(ctx context.Context, d *dashboardData) []string {
	var w []string
	cfg := d.Config
	if yaml, err := h.Admin.Read(ctx, cfg.Generation); err == nil {
		if chk, err := h.Admin.Validate(ctx, yaml); err == nil {
			for _, e := range chk.Errors {
				w = append(w, "Config problem: "+e)
			}
			for _, e := range chk.Warnings {
				w = append(w, "Config warning: "+e)
			}
		}
	}
	if len(cfg.Zones) == 0 {
		w = append(w, "No managed zones are configured: DNS-01 issuance and the DNS proxy have nothing to serve.")
	}
	if len(cfg.EnabledProviders()) == 0 {
		w = append(w, "No enabled providers: nothing can be issued.")
	}
	switch {
	case cfg.LDAP.URL == "":
		w = append(w, "LDAP is not configured: only the local administrator can log in.")
	default:
		h.mu.Lock()
		done, at, errText := h.ldapDone, h.ldapAt, h.ldapErr
		h.mu.Unlock()
		switch {
		case !done:
			w = append(w, "LDAP has not been tested since the broker started (Admin, Config, Test LDAP).")
		case errText != "":
			w = append(w, "The last LDAP test ("+fmtTime(at)+") failed: "+errText)
		}
	}
	for _, z := range d.Zones {
		if z.Hosted.HostedZoneID == "" {
			w = append(w, "Zone "+z.Zone.Name+": no hosted zone; DNS-01 fails for it: "+z.Hosted.Err)
		}
		switch {
		case z.Err != "":
			w = append(w, "Zone "+z.Zone.Name+": CAA could not be checked: "+z.Err)
		case !z.Status.WildcardProtected:
			w = append(w, "Zone "+z.Zone.Name+" is unprotected: "+z.Status.Detail)
		case len(z.Status.MissingProviders) > 0:
			w = append(w, "Zone "+z.Zone.Name+": CAA does not authorize provider(s) "+strings.Join(z.Status.MissingProviders, ", ")+"; fallback would fail.")
		}
		if z.Err == "" && z.Status.BrokerWildcard == core.BrokerNotPinned {
			w = append(w, "Zone "+z.Zone.Name+": CAA pins wildcards to other ACME accounts only; the broker itself cannot issue *."+
				z.Zone.Name+" (ACME proxy, direct API). Add an issuewild record with the broker's account if it should.")
		}
	}
	for _, a := range d.Accounts {
		if a.Err != "" {
			w = append(w, "Provider "+a.Provider+": "+a.Err)
		}
	}
	for _, ps := range d.Snapshot.Providers {
		if !ps.Open {
			w = append(w, fmt.Sprintf("Provider %s is %s until %s.", ps.Name, ps.State.Health, fmtTime(ps.State.RetryAfter)))
		}
	}
	return w
}

// recordLDAPTest remembers the outcome of the last LDAP test for the dashboard.
func (h *Handler) recordLDAPTest(err error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.ldapDone, h.ldapAt = true, h.Clock.Now()
	h.ldapErr = ""
	if err != nil {
		h.ldapErr = err.Error()
	}
}
