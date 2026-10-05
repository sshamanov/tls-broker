package ui

import (
	"context"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"time"

	"tls-broker/internal/auth"
	"tls-broker/internal/core"
	"tls-broker/internal/ctlog"
)

// CTInventory is the Certificate Transparency inventory of the managed
// zones (*ctlog.Inventory).
type CTInventory interface {
	Snapshot() ctlog.Snapshot
}

// ctPanelLimit is how many rows each CT panel of the status page lists.
const ctPanelLimit = 8

// ctView is the CT inventory as the pages show it.
type ctView struct {
	// Status: off (switched off or not wired), loading (no refresh has
	// finished yet), unavailable (every zone failed and nothing is
	// known), ready.
	Status     string
	Snap       ctlog.Snapshot
	Report     ctlog.Report
	Certs      []ctCert
	Recent     []ctlog.Recent
	Zones      int // queried zones plus the managed zones inside them
	Stale      []ctlog.ZoneStatus
	Refreshing bool
}

// ctCert is a set with its lifetime bar.
type ctCert struct {
	ctlog.Cert
	Life lifetime
}

// ctReport analyses the inventory at now. The broker's own certificates
// (both modes, including recently expired ones) are matched by serial.
func (h *Handler) ctReport(ctx context.Context, now time.Time) (*ctView, error) {
	v := &ctView{Status: "off"}
	if h.Inventory == nil {
		return v, nil
	}
	v.Snap = h.Inventory.Snapshot()
	if !v.Snap.Enabled {
		return v, nil
	}
	v.Refreshing = v.Snap.Refreshing
	v.Zones = len(v.Snap.ManagedZones)
	if !v.Snap.Loaded() {
		v.Status = "loading"
		return v, nil
	}
	certs, err := h.Certs.List(ctx, core.CertificateFilter{ValidAt: now.Add(-ctlog.Lookback), Limit: countCap})
	if err != nil {
		return nil, err
	}
	serials := map[string]bool{}
	for _, c := range certs {
		serials[normSerial(c.Serial)] = true
	}
	v.Report = ctlog.Analyze(v.Snap, now, func(s string) bool { return serials[normSerial(s)] })
	for _, c := range v.Report.Certs {
		v.Certs = append(v.Certs, newCTCert(c, now))
	}
	v.Recent = v.Report.Recent
	v.Stale = v.Snap.Failed()
	v.Status = "ready"
	if len(v.Stale) == len(v.Snap.Zones) && len(v.Snap.Issuances) == 0 && len(v.Snap.Zones) > 0 {
		v.Status = "unavailable"
	}
	return v, nil
}

// normSerial is a hex serial in lower case without leading zeros.
func normSerial(s string) string { return strings.TrimLeft(strings.ToLower(s), "0") }

func newCTCert(c ctlog.Cert, now time.Time) ctCert {
	l := newLifetime(now, c.NotBefore, c.NotAfter, c.RenewAt)
	l.RenewExpected = true
	l.State = string(c.State)
	if c.State == ctlog.StateOverdue || c.State == ctlog.StateRevoked {
		l.State = "expired" // the bar's red
	}
	return ctCert{Cert: c, Life: l}
}

// UpdatedAt is when the data was last refreshed.
func (v *ctView) UpdatedAt() time.Time { return v.Snap.LastEnd }

// Top are the first rows of the status page panel.
func (v *ctView) Top() []ctCert { return v.Certs[:min(len(v.Certs), ctPanelLimit)] }

// TopRecent are the first rows of the recent issuance panel.
func (v *ctView) TopRecent() []ctlog.Recent { return v.Recent[:min(len(v.Recent), ctPanelLimit)] }

// ctWarnings are the admin "Needs attention" items of the inventory.
func ctWarnings(v *ctView) []string {
	var w []string
	if v == nil || v.Status == "off" || v.Status == "loading" {
		return w
	}
	for _, z := range v.Stale {
		last := "never"
		if !z.LastSuccess.IsZero() {
			last = fmtTime(z.LastSuccess)
		}
		w = append(w, fmt.Sprintf("Certificate Transparency: zone %s could not be refreshed (last success %s): %s", z.Zone, last, z.Err))
	}
	byState := map[ctlog.State][]string{}
	var unexpected []string
	for _, c := range v.Report.Certs {
		byState[c.State] = append(byState[c.State], c.Key())
		if c.UnexpectedCA {
			unexpected = append(unexpected, c.Key()+": "+c.CAADetail)
		}
	}
	add := func(st ctlog.State, what string) {
		if list := byState[st]; len(list) > 0 {
			w = append(w, fmt.Sprintf("Certificate Transparency: %s %s: %s.", plural(len(list), "certificate", "certificates"), what, nameList(list)))
		}
	}
	add(ctlog.StateExpired, "expired without a renewal")
	add(ctlog.StateOverdue, "close to expiry without a renewal")
	add(ctlog.StateRevoked, "revoked without a replacement")
	if len(unexpected) > 0 {
		w = append(w, fmt.Sprintf("Certificate Transparency: %s from a CA the zone's CAA does not allow: %s.",
			plural(len(unexpected), "certificate", "certificates"), nameList(unexpected)))
	}
	return w
}

// nameList joins up to five entries with "and N more".
func nameList(list []string) string {
	if len(list) <= 5 {
		return strings.Join(list, "; ")
	}
	return strings.Join(list[:5], "; ") + fmt.Sprintf("; and %d more", len(list)-5)
}

func plural(n int, one, many string) string {
	if n == 1 {
		return "1 " + one
	}
	return fmt.Sprintf("%d %s", n, many)
}

// ctState is a state in words, for badges and filters.
func ctState(s ctlog.State) string {
	switch s {
	case ctlog.StateDue:
		return "renewal due"
	case ctlog.StateOK:
		return "ok"
	}
	return string(s)
}

// ctFilter values of the full list.
var ctStateFilters = []struct{ Value, Label string }{
	{"", "Any"}, {"attention", "Needs attention"}, {"due", "Renewal due"}, {"ok", "OK"},
	{"expired", "Expired"}, {"replaced", "Replaced"},
}

type ctListData struct {
	CT                  *ctView
	Q, Zone, State, Src string
	ZoneNames           []string
	States              []struct{ Value, Label string }
	Rows                []ctCert
}

// ctList is "All in managed zones": every identifier set the inventory
// knows, filtered by zone, state, source and name.
func (h *Handler) ctList(w http.ResponseWriter, r *http.Request, cur *auth.Current) {
	q := r.URL.Query()
	d := &ctListData{Q: strings.ToLower(strings.TrimSpace(q.Get("q"))), Zone: q.Get("zone"), State: q.Get("state"),
		Src: q.Get("source"), States: ctStateFilters}
	v, err := h.ctReport(r.Context(), h.Clock.Now())
	if err != nil {
		h.serverError(w, r, cur, "list certificates", err)
		return
	}
	d.CT = v
	d.ZoneNames = v.Snap.ManagedZones
	slices.Sort(d.ZoneNames)
	for _, c := range v.Certs {
		if d.Q != "" && !strings.Contains(c.Key(), d.Q) {
			continue
		}
		if d.Zone != "" && !slices.Contains(c.Zones, d.Zone) {
			continue
		}
		if d.Src != "" && c.Source != d.Src {
			continue
		}
		switch d.State {
		case "":
		case "attention":
			if !c.Problem() {
				continue
			}
		default:
			if string(c.State) != d.State {
				continue
			}
		}
		d.Rows = append(d.Rows, c)
	}
	h.render(w, http.StatusOK, "ct_list", h.newPage(w, r, cur, "Certificates", "certificates", d))
}
