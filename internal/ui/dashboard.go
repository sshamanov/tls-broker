package ui

import (
	"context"
	"fmt"
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
	Counts   dashCounts
	Recent   []core.AuditEvent
	Warnings []string
	Zones    []zoneView
	Accounts []accountView
	Config   *core.Config
}

type dashCounts struct {
	ACMECerts  string
	Orders     string
	Direct     int
	DirectLive int
}

type zoneView struct {
	Zone    core.ZoneConfig
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

func capped(n int) string {
	if n >= countCap {
		return fmt.Sprintf("%d+", countCap)
	}
	return fmt.Sprint(n)
}

func (h *Handler) dashboard(w http.ResponseWriter, r *http.Request, cur *auth.Current) {
	d := &dashboardData{Snapshot: h.Scheduler.Snapshot(), Config: h.Config.Current()}
	p := h.newPage(w, r, cur, "Dashboard", "dashboard", d)
	if cur.User.Blocked {
		h.render(w, http.StatusOK, "dashboard", p)
		return
	}
	ctx := r.Context()
	now := h.Clock.Now()

	if certs, err := h.Certs.List(ctx, core.CertificateFilter{Mode: core.ModeACME, ValidAt: now, Limit: countCap}); err != nil {
		h.serverError(w, r, cur, "list certificates", err)
		return
	} else {
		d.Counts.ACMECerts = capped(len(certs))
	}
	if active, err := h.Orders.ListActive(ctx); err != nil {
		h.serverError(w, r, cur, "list orders", err)
		return
	} else {
		d.Counts.Orders = capped(len(active))
	}
	entries, err := h.Direct.List(ctx)
	if err != nil {
		h.serverError(w, r, cur, "list direct entries", err)
		return
	}
	d.Counts.Direct = len(entries)
	for _, e := range entries {
		if e.NotAfter.After(now) {
			d.Counts.DirectLive++
		}
	}
	if d.Recent, err = h.Audit.Query(ctx, core.AuditQuery{IncludeAdmin: p.Admin, Limit: 10}); err != nil {
		h.Logger.Warn("ui: audit query failed", "error", err)
		p.Flash = firstFlash(p.Flash, &flash{Kind: "error", Text: "The audit log could not be read."})
	}

	if p.Admin {
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
	for i, z := range cfg.Zones {
		wg.Add(1)
		go func() {
			defer wg.Done()
			zv := zoneView{Zone: z}
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

// suggestCAA builds the CAA records that restrict wildcard issuance in a zone
// to the broker's own accounts.
func suggestCAA(zone string, accounts []accountView) []string {
	var out []string
	for _, a := range accounts {
		if a.URL == "" || len(a.Issuers) == 0 {
			continue
		}
		for _, tag := range []string{"issue", "issuewild"} {
			out = append(out, fmt.Sprintf(`%s. CAA 0 %s "%s; accounturi=%s"`, zone, tag, a.Issuers[0], a.URL))
		}
	}
	return out
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
		switch {
		case z.Err != "":
			w = append(w, "Zone "+z.Zone.Name+": CAA could not be checked: "+z.Err)
		case !z.Status.WildcardProtected:
			w = append(w, "Zone "+z.Zone.Name+" is unprotected: "+z.Status.Detail)
		case len(z.Status.MissingProviders) > 0:
			w = append(w, "Zone "+z.Zone.Name+": CAA does not authorize provider(s) "+strings.Join(z.Status.MissingProviders, ", ")+"; fallback would fail.")
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
