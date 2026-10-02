// Package sched is the central admission scheduler (architecture §10). It
// implements core.Scheduler and core.Ticket.
//
// Per provider it combines three things:
//
//   - Concurrency slots: at most ProviderLimits.Concurrency upstream
//     preparations run at once. Waiters are served by priority class, then
//     by arrival, for at most AdmissionRequest.MaxWait.
//   - Rate budgets: sliding-window counters (new orders per account,
//     certificates per registered domain, certificates per exact identifier
//     set). Every admitted request reserves one unit of each budget it
//     touches; the reservation is persisted through core.BudgetStore and
//     settled by the Ticket (commit or refund). A share of every budget is
//     reserved for renewals. An exhausted budget refuses at once.
//   - Provider circuit: rate-limit, busy and outage signals reported through
//     ReportProvider close admission until a computed time; the state is
//     persisted through core.ProviderStateStore and restored by New.
//
// The working state lives in memory; the stores are written through so that
// reservations and circuits survive a restart. All time comes from a
// core.Clock. docs/rate-limits.md describes the model for operators.
package sched
