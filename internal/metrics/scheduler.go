package metrics

import (
	"github.com/prometheus/client_golang/prometheus"

	"tls-broker/internal/core"
)

// schedulerCollector reads core.Scheduler.Snapshot at scrape time.
type schedulerCollector struct {
	snap func() core.SchedulerSnapshot
}

func schedDesc(name, help string, labels ...string) *prometheus.Desc {
	return prometheus.NewDesc(ns+"_scheduler_"+name, help, labels, nil)
}

var (
	slotsInUseDesc = schedDesc("slots_in_use", "Concurrency slots in use per provider.", "provider")
	slotsTotalDesc = schedDesc("slots_total", "Concurrency slots configured per provider.", "provider")
	waitersDesc    = schedDesc("waiters", "Requests waiting for a slot per provider.", "provider")
	reservedDesc   = schedDesc("reservations", "Open budget reservations per provider.", "provider")
	circuitDesc    = schedDesc("circuit_open", "1 while admission to the provider is closed (circuit open: rate limited or down), else 0.", "provider")
	stateDesc      = schedDesc("provider_state", "1 for the provider's current health state (healthy, rate_limited, down), 0 for the others.", "provider", "state")
	budgetUsedDesc = schedDesc("budget_used", "Budget used (reserved plus committed) inside the window.", "provider", "kind", "key")
	budgetLimDesc  = schedDesc("budget_limit", "Budget limit per window.", "provider", "kind", "key")
	budgetRemDesc  = schedDesc("budget_remaining", "Budget remaining (limit minus used, not below 0).", "provider", "kind", "key")
)

func (c *schedulerCollector) Describe(ch chan<- *prometheus.Desc) {
	for _, d := range []*prometheus.Desc{slotsInUseDesc, slotsTotalDesc, waitersDesc, reservedDesc,
		circuitDesc, stateDesc, budgetUsedDesc, budgetLimDesc, budgetRemDesc} {
		ch <- d
	}
}

func (c *schedulerCollector) Collect(ch chan<- prometheus.Metric) {
	snap := c.snap()
	g := prometheus.GaugeValue
	for _, p := range snap.Providers {
		ch <- prometheus.MustNewConstMetric(slotsInUseDesc, g, float64(p.SlotsInUse), p.Name)
		ch <- prometheus.MustNewConstMetric(slotsTotalDesc, g, float64(p.SlotsTotal), p.Name)
		ch <- prometheus.MustNewConstMetric(waitersDesc, g, float64(p.Waiting), p.Name)
		ch <- prometheus.MustNewConstMetric(reservedDesc, g, float64(p.Reserved), p.Name)
		closed := 1.0
		if p.Open {
			closed = 0
		}
		ch <- prometheus.MustNewConstMetric(circuitDesc, g, closed, p.Name)
		cur := p.State.Health
		if cur == "" {
			cur = core.ProviderHealthy
		}
		for _, st := range []core.ProviderHealth{core.ProviderHealthy, core.ProviderLimited, core.ProviderUnavailable} {
			v := 0.0
			if st == cur {
				v = 1
			}
			ch <- prometheus.MustNewConstMetric(stateDesc, g, v, p.Name, string(st))
		}
		for _, b := range p.Budgets {
			rem := b.Limit - b.Used
			if rem < 0 {
				rem = 0
			}
			k, key := string(b.Kind), b.Key
			ch <- prometheus.MustNewConstMetric(budgetUsedDesc, g, float64(b.Used), p.Name, k, key)
			ch <- prometheus.MustNewConstMetric(budgetLimDesc, g, float64(b.Limit), p.Name, k, key)
			ch <- prometheus.MustNewConstMetric(budgetRemDesc, g, float64(rem), p.Name, k, key)
		}
	}
}
