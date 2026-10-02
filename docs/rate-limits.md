# Rate limits and admission

Upstream CA rate limits are the broker's scarcest resource. Every request that
could create upstream issuance — clean ACME `newOrder`, a direct-mode cache
miss or renewal, a scheduled renewal — passes the admission scheduler
(`internal/sched`) before anything is sent to the CA. The DNS proxy is the one
exception: there the client runs the ACME flow itself. Design background:
architecture §10.

The scheduler is synchronous. A request is admitted at once, waits a bounded
time for a free slot, or is refused with a retry time. There is no queue of
work that survives a restart; only budget reservations and provider circuit
state are persisted.

## The model

Each provider (upstream CA account) has three independent controls. A request
is checked against them in this order.

### 1. Provider circuit

When a provider signals trouble, admission to it closes until a computed
time. The issuance engine reports the outcome of every upstream call to the
scheduler:

| Upstream result | Admission | Closed for |
|---|---|---|
| rate limited (ACME `rateLimited`, HTTP 429) | closed, state `rate_limited` | the CA's `Retry-After`, else `rate_limit_retry_after` |
| busy (503 with `Retry-After`) | closed, state `rate_limited` | the CA's `Retry-After`, else `busy_retry_after` |
| down (transport error, timeout, 5xx without `Retry-After`) | closed, state `down` | the CA's `Retry-After`, else `down_retry_after` doubled for each consecutive failure after the first, capped at `down_retry_after_max` |
| success | unchanged; failure count reset | a closure whose time has passed is cleared |
| rejected, `alreadyReplaced`, cancelled | ignored | these say nothing about provider health |

- A new signal never shortens a closure already in force.
- Closing admission also refuses every request already waiting for a slot of
  that provider. Nothing is admitted while admission is closed.
- After a `down` closure ends, exactly one probe request is admitted. Others
  are refused until the probe reports back or finishes its preparation. A
  successful probe returns the provider to `healthy`; a failed one closes
  admission again with a longer backoff.
- Circuit state is persisted on every change and restored at startup, so a
  restart does not forget an upstream `Retry-After`.
- Opening and closing are recorded in the audit log as `provider_state`
  events (admin-only).

### 2. Rate budgets

Three sliding-window counters per provider, kept below the CA's real limits:

| Budget | Key | Spent by |
|---|---|---|
| new orders per account | — | every upstream `newOrder` |
| certificates per registered domain | registered domain (public suffix + 1) | each issued certificate, once per distinct registered domain in it |
| certificates per exact identifier set | the normalized set | each issued certificate |

A budget allows `count` events in any `window`. Events are counted while they
are inside the window: an event at time `t` stops counting at `t + window`.

**Reserve, commit, refund.** On admission one unit of every budget the request
touches is *reserved* and written to the database before the request
continues. A reservation counts like a spent unit, so concurrent requests
cannot overshoot. The ticket then settles it:

| Step | New-order unit | Certificate units |
|---|---|---|
| `OrderCreated` (just before upstream `newOrder`) | spent for good | still reserved |
| `Commit` (certificate issued) | spent if the order was created, else returned | spent |
| `Refund` (order expired, abandoned, or failed before or at finalize) | spent if the order was created, else returned | returned |

The first of `Commit` and `Refund` wins; every ticket method is idempotent and
safe in any order. An abandoned order therefore never costs certificate
budget, and an upstream order is always counted once it may exist.

**Renewal headroom.** `renewal_reserve_percent` of every budget is kept for
renewals. A request that is not a renewal is refused once usage reaches
`count × (100 − percent) / 100` (rounded down, never below 1). Renewals may
use the whole `count`.

**Exhausted means refused now.** When any budget has no room the request is
refused at once: waiting a few seconds would not help. The refusal carries the
time at which enough counted events will have left the window for the request
to fit. If several budgets are exhausted, the latest of those times wins.

**Exemptions.**

- *ARI-qualified renewals* (the order carries `replaces`, the provider is
  configured `ari_exempt: true` and now is inside the CA's suggested renewal
  window) reserve no budget at all; they only take a concurrency slot. Let's
  Encrypt exempts these orders from its limits (architecture §8).
- *Adopting an abandoned upstream order* spends no new-order budget, since no
  new upstream order is created; certificate budgets apply as usual.

Usage is recorded even for a budget whose `count` is 0 (not enforced), so the
UI shows it and enabling a limit takes effect with its history.

### 3. Concurrency slots

At most `concurrency` upstream preparations (order + DNS-01) run at once per
provider. A request that finds every slot taken waits. Free slots go to
waiting requests by priority class first, then in arrival order within a
class:

| Class | Requests |
|---|---|
| 1 | ARI-qualified renewals |
| 2 | direct-cache certificates inside the emergency window |
| 3 | clean ACME renewals inside the emergency window |
| 4 | ordinary clean ACME issuance and renewal |
| 5 | direct-cache misses |
| 6 | direct-cache background renewals |

The wait is bounded by `scheduler.admit_wait` (a caller may ask for a
different wait, or none). A request whose wait runs out, or whose client goes away,
gives its budget reservation back and holds nothing. The slot is released
when preparation finishes (the order is ready to finalize), not when the
certificate is issued, so slow finalizations do not block new orders.

## Configuration

Per provider, under `providers[].limits` (see `configuration.md`):

| Key | Default | Meaning |
|---|---|---|
| `new_orders` | `{count: 200, window: 3h}` | upstream newOrder calls per account (Let's Encrypt: 300 / 3 h) |
| `certs_per_domain` | `{count: 40, window: 7d}` | certificates per registered domain (Let's Encrypt: 50 / 7 d) |
| `certs_per_set` | `{count: 4, window: 7d}` | certificates per exact identifier set (Let's Encrypt: 5 / 7 d) |
| `concurrency` | `4` | parallel upstream preparations |
| `renewal_reserve_percent` | `25` | share of every budget only renewals may use |

A `count` of 0 disables that budget. Under `scheduler`:

| Key | Default | Meaning |
|---|---|---|
| `admit_wait` | `20s` | longest wait for a slot |
| `busy_retry_after` | `30s` | `Retry-After` when no slot became free; closure after a "busy" signal without `Retry-After`; retry hint while a probe is in flight |
| `down_retry_after` | `1m` | first closure after an outage signal without `Retry-After` |
| `down_retry_after_max` | `30m` | cap of the doubling outage backoff |
| `rate_limit_retry_after` | `1h` | closure after a rate-limit signal without `Retry-After` |

Configuration changes apply without a restart: new limits apply to the next
request, added slots are handed to waiting requests at once, and a longer
window loads older events from the database so that past usage counts.
Lowering `concurrency` below the number of running preparations admits no one
until enough of them finish.

## What a client sees

| Situation | Response |
|---|---|
| a budget is exhausted | `429`, `urn:ietf:params:acme:error:rateLimited`, `Retry-After` = time until the budget has room |
| no slot within `admit_wait` | `429` `rateLimited`, `Retry-After` = `busy_retry_after` |
| provider rate limited / asked to back off | `429` `rateLimited`, `Retry-After` = time until the closure ends |
| provider down | `503` `serverInternal`, `Retry-After` = time until the closure ends |

The ACME server and the direct API both build these responses with
`core.ProblemFromError`, so the status and `Retry-After` are the same in both
modes.

The issuance engine tries the next eligible provider before refusing (new
certificates only; renewals stay on their provider unless in the emergency
window). The client sees a refusal only when no provider admitted the request,
with the smallest retry time among them; `503` only when every provider was
down. The problem detail names the exhausted budget (for example
"certificates per registered domain example.com"), never upstream error text.
The scheduler does not audit refusals itself; the code that answers the
client records them with the full request context.

## Restart

- Reserved and committed budget events are rows in the database. At startup
  the scheduler loads every event inside the longest configured window plus
  every still-reserved event, whatever its age.
- A reservation whose order was in flight survives as an *open reservation*.
  Startup recovery (`issuance`) lists them (`OpenRefs`) and settles each
  through `Reattach`: committed if the certificate was issued, refunded
  otherwise. A reattached ticket holds no slot.
- `OrderCreated` is persisted before the upstream `newOrder` call, so a crash
  between the two still counts the order.
- Slots and waiting requests are not persisted: clients whose requests were
  waiting retry on their own.
- Circuit state, including the time a closure ends, is restored as saved.

Committed events that have left every window are deleted by the scheduler's
`Prune`, which the application runs from its periodic housekeeping.

## Tuning

- Keep budgets below the CA's limits, not equal to them. The CA counts things
  the broker cannot see (certificates issued for the same domain elsewhere,
  manual issuance), and its buckets refill differently from a sliding window.
- If the UI shows a domain budget close to its limit, many hosts share one
  registered domain. Combine names into fewer certificates or raise
  `renewal_reserve_percent` so that renewals stay safe while new issuance
  backs off.
- `certs_per_set` protects against clients that loop on issuance; 4 per week
  allows a few re-issues while staying under Let's Encrypt's 5.
- Raise `concurrency` when many orders are refused as busy while budgets have
  room; lower it if the CA answers with busy signals or DNS propagation is
  the bottleneck.
- `admit_wait` should stay below the HTTP timeouts of clients (Certbot: 45 s).
- For a CA with tighter limits (Google Trust Services: 100 newOrder per hour
  per project), set that provider's `new_orders` accordingly; budgets are per
  provider.
