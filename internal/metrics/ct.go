package metrics

import (
	"sort"
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

// CTStats is the Certificate Transparency inventory at scrape time.
type CTStats struct {
	// States counts identifier sets by the state of their current
	// certificate; the caller lists every state, zero counts included.
	States map[string]int
	// UnexpectedCA counts sets whose CA the zone's CAA does not allow.
	UnexpectedCA int
	Zones        []CTZone
}

// CTZone is the refresh state of one queried zone.
type CTZone struct {
	Zone        string
	LastSuccess time.Time // zero: never
	OK          bool      // the last attempt succeeded
}

var (
	ctCertsDesc = prometheus.NewDesc(ns+"_ct_certificates",
		"Identifier sets in the managed zones seen in Certificate Transparency, by the state of their newest certificate.", []string{"state"}, nil)
	ctUnexpectedDesc = prometheus.NewDesc(ns+"_ct_unexpected_ca_certificates",
		"Identifier sets whose newest certificate comes from a CA the zone's CAA does not allow.", nil, nil)
	ctSuccessDesc = prometheus.NewDesc(ns+"_ct_last_success_timestamp_seconds",
		"Unix time of the last complete CT refresh of a queried zone; 0 before the first.", []string{"zone"}, nil)
	ctUpDesc = prometheus.NewDesc(ns+"_ct_zone_up",
		"1 when the last CT refresh of a queried zone succeeded, else 0.", []string{"zone"}, nil)
)

// ctCollector reads the CT inventory at scrape time.
type ctCollector struct{ stats func() CTStats }

func (c *ctCollector) Describe(ch chan<- *prometheus.Desc) {
	for _, d := range []*prometheus.Desc{ctCertsDesc, ctUnexpectedDesc, ctSuccessDesc, ctUpDesc} {
		ch <- d
	}
}

func (c *ctCollector) Collect(ch chan<- prometheus.Metric) {
	s := c.stats()
	g := prometheus.GaugeValue
	states := make([]string, 0, len(s.States))
	for st := range s.States {
		states = append(states, st)
	}
	sort.Strings(states)
	for _, st := range states {
		ch <- prometheus.MustNewConstMetric(ctCertsDesc, g, float64(s.States[st]), st)
	}
	ch <- prometheus.MustNewConstMetric(ctUnexpectedDesc, g, float64(s.UnexpectedCA))
	for _, z := range s.Zones {
		ts := 0.0
		if !z.LastSuccess.IsZero() {
			ts = float64(z.LastSuccess.Unix())
		}
		up := 0.0
		if z.OK {
			up = 1
		}
		ch <- prometheus.MustNewConstMetric(ctSuccessDesc, g, ts, z.Zone)
		ch <- prometheus.MustNewConstMetric(ctUpDesc, g, up, z.Zone)
	}
}
