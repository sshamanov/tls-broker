# Issuance engine

The issuance engine (`internal/issuance`, `core.Issuer`) is the part of the
broker between a gate-approved request and a stored certificate. It decides
what kind of request this is (new certificate, renewal, ARI-qualified
renewal, emergency), which upstream CA serves it, what `replaces` to send,
whether an abandoned upstream order can be reused, and how an order survives
a restart. Everything it touches goes through a port: upstream CAs are
`core.Provider`, Route53 is `core.DNSEngine`, admission is `core.Scheduler`,
state is the `core` stores. Design background: architecture §7, §8, §9, §10,
§11, §20.

The engine does not authorize. Front ends run the gate and pass the
`Decision`; the engine only verifies it (and runs the gate itself when a
caller passes a zero decision). The same holds for `Finalize`: the gate is
checked again for the address that finalizes, which may differ from the one
that created the order — by the front end, which passes
`FinalizeRequest.Decision`, or by the engine when that is zero. A retry of an
already accepted CSR is a poll and is not gated by either.

## Order state machine

An `Order` is one issuance attempt, for a downstream ACME order (`acme`) or
one direct-mode job (`direct`). It has two independent dimensions: `Status`
is what the client sees, `Prep` is how far the upstream order has come.

```text
                 Admit / Issue
                      │  FindOpen → reuse  (acme, same account + set)
                      │  classify, choose provider, Scheduler.Acquire
                      ▼
   ┌──────────────────────────────────────┐   CreateAdopting
   │ Status ready      Prep intent        │◄──────────────────────┐
   │ (row persisted; nothing upstream)    │                       │
   └──────────────┬───────────────────────┘                       │
        Ticket.OrderCreated → Provider.NewOrder                   │
        (alreadyReplaced → Refund, re-Acquire, NewOrder again)    │
                  │ SetUpstream(URL)                              │
                  ▼                                               │
   ┌──────────────────────────────────────┐                       │
   │ Status ready      Prep preparing     │                       │
   │ DNSChallenges → Present (all) →      │                       │
   │ Accept (all) → WaitReady → CleanupOwner                      │
   └──────────────┬───────────────────────┘                       │
                  │ SetPrepared, Ticket.PrepDone (slot released)   │
                  ▼                                               │
   ┌──────────────────────────────────────┐   ExpireDue (TTL)     │
   │ Status ready      Prep prepared      │──────────────────────►│ invalid, Prep prepared:
   │ waiting for the client's CSR         │   Refund, cleanup     │ "adoptable" by the next
   └──────────────┬───────────────────────┘                       │ order for the same set
                  │ BeginFinalize (CSR hash recorded once)        │ and provider
                  ▼                                               │
   ┌──────────────────────────────────────┐                       │
   │ Status processing                    │                       │
   │ Provider.Finalize → WaitCertificate  │                       │
   │ → verify chain → Complete, Commit    │                       │
   └──────┬───────────────────────┬───────┘
          ▼                       ▼
   ┌─────────────┐        ┌──────────────────┐
   │ valid       │        │ invalid (Error)  │  Fail: Refund, cleanup;
   │ CertificateID        │ Prep failed      │  Prep stays prepared only if
   └─────────────┘        └──────────────────┘  it already was
```

Rules the diagram relies on:

- **One downstream order, at most one upstream order.** `Provider.NewOrder`
  is called at most once per order, after the row with its upstream intent
  is durable and after `Ticket.OrderCreated`; the URL is persisted right
  after. A crash between the two leaves `intent` without URL, which recovery
  turns into `invalid` with the new-order budget counted as spent.
- **`BeginFinalize` may happen before preparation is done.** The CSR is
  recorded, the status becomes `processing`, and the preparing goroutine
  continues into finalize when it is ready. Exactly one goroutine owns an
  order at any time; the hand-off is an in-memory `job` per order.
- **Same CSR again** returns the current state; **a different CSR** is
  `ErrCSRMismatch` (`badCSR` downstream) and never reaches upstream.
  A CSR that does not match the order's identifiers exactly (SANs plus common
  name, normalized) is `badCSR` and records nothing.
- **Once the CSR is recorded the issuance detaches from the request.**
  `finalizeOrder` runs under a background context bounded by
  `upstream.prepare_timeout`, not the HTTP request's. `Finalize` and `Issue`
  only *wait* for it; a client that leaves gets `processing` (ACME) or its
  context error (direct) while the certificate is still issued and stored.
  The next poll, or the next direct fetch, finds it.
- **A lost finalize response is checked, not retried.** If
  `Provider.Finalize` fails with a health error (down, busy, rate limited) or
  a context error, the engine asks `GetOrder`: an order that is `processing`
  or `valid` accepted the CSR and the engine proceeds to `WaitCertificate`.
- **Chain verification** before storing: the chain parses, the leaf carries
  the CSR's public key and exactly the order's names, is not expired, and
  every link's signature verifies. Trust anchors are not checked (that is the
  CA's job and the client's).
- **Certificates are created only by `OrderStore.Complete`**, which also
  marks the predecessor replaced. `ReplacesID` is the broker certificate
  whose ARI identifier was sent as `replaces`.

### Direct mode

`Issue` runs the same machine synchronously: admission and preparation under
the caller's context (a cancelled caller fails and refunds the attempt — the
upstream order stays adoptable if it was already prepared), then
`BeginFinalize` with the caller's CSR and a wait on the background finalize.
Direct orders have `AccountID` empty, `Mode direct`, and the store keeps no
chain for them: `Issue` returns `Certificate.ChainPEM` in memory and the
direct cache writes it to disk.

## Timing budget

Clients are impatient (`docs/plan.md`, "Client limits": Certbot 45 s per
request and 90 s of polling after finalize; acme.sh 30 polls). The engine
holds requests only where waiting is useful and never for upstream work.

| Step | Held for | Knob | Default | Must stay below |
|---|---|---|---|---|
| `newOrder` → `Admit`: wait for a concurrency slot | `scheduler.admit_wait` | 20 s | Certbot's 45 s request timeout |
| budget exhausted / circuit closed | not held: `429`/`503` with `Retry-After` at once | | |
| `finalize` → `Finalize`: wait for preparation + issuance | `scheduler.finalize_wait` | 20 s | 45 s; then `processing` + `scheduler.processing_retry_after` (3 s) and the client polls |
| preparation (newOrder, Route53 change, propagation, CA validation) | background | `upstream.prepare_timeout` | 10 min | the order TTL (15 min) |
| order never finalized | | `scheduler.order_ttl` | 15 min | — (refund, upstream order kept for adoption) |
| direct `Issue` (whole synchronous flow) | caller's context | `direct.issue_timeout` (set by the direct cache) | 4 min | the HTTP write timeout |

Preparation starts the moment the slot is granted, while the client is still
generating its key and CSR, so in the common case the TXT value is already
visible when `finalize` arrives and the client sees `valid` within a few
seconds.

Observed against Let's Encrypt staging with real Route53 (2026-10-03): a
Certbot new issuance took 37 s end to end (finalize held the full 20 s, then
`processing`, certificate at +33 s); an acme.sh DNS-proxy `present` 26.5 s;
a first direct fetch 33 s. The Route53 change reaching `INSYNC` dominates;
the defaults above leave room for it.

## Logging

Every step is logged through the engine's `*slog.Logger` with the order ID
(`order=`), so `grep order=<id>` reconstructs one issuance:

- info: `order admitted` (mode, names, provider, class, renewal, ARI,
  replaces, adoption, admission wait), `order prepared` (upstream order URL,
  preparation duration), `certificate issued` (serial, expiry, finalize
  duration, order age), `order failed`, `order expired`, recovery decisions;
- debug: each upstream call (`upstream newOrder`, `getOrder`, `challenge
  accepted`, `order validated`, `finalize (CSR sent)`, `certificate`) and
  each DNS-01 phase (`presenting DNS-01 values`, `DNS-01 values visible`)
  with durations and the provider's error, if any.

Run with `TLS_BROKER_LOG_LEVEL=debug` to see where time goes in a slow
issuance (Route53 propagation versus CA validation versus finalize).

## Classification

Every `Admit` and `Issue` first observes the request on the **lineage** (the
normalized identifier set, `names.Set.Key()`) and loads the lineage's newest
certificate from any provider.

| Fact | Meaning |
|---|---|
| no certificate for the set | **new certificate** |
| a certificate exists (even expired) | **renewal**: may use renewal-reserved budget headroom; sticky to that certificate's provider |
| `now ≥ NotAfter − emergency_window` | **emergency**: fallback providers may be tried (below); priority class 2 (direct) or 3 (ACME) |
| provider exempts ARI and `now` is inside the predecessor's suggested window | **ARI-qualified**: priority 1, no budget reserved |

The emergency window is architecture §8 exactly (`core.EmergencyWindow`):

```text
emergency_window = fraction × lifetime + safety_checks × observed_interval
                   capped at lifetime / 2
```

`observed_interval` is the lineage's smoothed gap between requests (ARI
polls, renewal orders, direct fetches), `emergency.default_interval` until
two requests have been seen. The observation made for the current request
counts: a client that returns after a long silence is treated as a client
that checks rarely, which is what makes its renewal an emergency sooner. A
client that checks daily gets 7.5 days on a 90-day certificate, weekly 25.5
days (both verified in the tests through the provider choice they cause).

Priority classes (architecture §10):

| Class | When |
|---|---|
| 1 `ari_renewal` | ARI-qualified (either mode) |
| 2 `direct_emergency` | direct renewal inside the emergency window |
| 3 `acme_emergency` | ACME renewal inside the emergency window |
| 4 `acme_ordinary` | everything else ACME |
| 5 `direct_miss` | direct cache miss (no certificate yet), or a foreground re-issue |
| 6 `direct_background` | direct renewal started behind a served response |

## Provider choice and emergency switching

`Providers.Enabled()` lists providers in order of preference; the first is
the primary. The engine builds an ordered list of candidates and asks the
scheduler for each in turn; the first admission wins, and the order's
`Provider` never changes afterwards.

```text
new certificate            primary, then every other enabled provider
renewal, provider healthy  the lineage's provider only
renewal, emergency         the lineage's provider, then the others
lineage provider disabled  like a new certificate (fresh issuance elsewhere)
```

"Refused" means the scheduler refused: closed circuit (the provider reported
an outage or a `Retry-After`), exhausted budget, or no slot within
`admit_wait`. A renewal with plenty of lifetime on a broken primary therefore
gets a **clean temporary error** (`503` with `Retry-After`, or `429` when the
closure came from a rate limit) and nothing is created elsewhere; the client
retries later. Inside the emergency window the same request is admitted at
the fallback: a **provider migration**, audited as `provider_failover`. The
migrated order carries no `replaces` (ARI continuity is not preserved across
CAs) and the lineage follows it: later renewals stay on the fallback until
*it* breaks.

When every candidate refuses, the client sees one `*AdmissionError`:
`provider_down` only if all were down, otherwise the rate-limit/busy refusal
with the smallest `Retry-After`; the provider name is kept only when a single
provider was asked.

A provider that fails *after* admission (upstream `429`, `503`, outage during
`NewOrder` or validation) fails that order — the order already belongs to
that provider — and the failure is reported to the scheduler, which closes
the circuit. The client's next order is then refused locally or falls back,
and nothing further is sent to the broken provider until its `Retry-After`.

## ARI handling

Architecture §8 "ARI rules the broker follows", as implemented:

- **`RenewalInfo(certID)`** finds the broker's certificate, observes the
  lineage (this is the client's "check"), and asks the certificate's
  provider — even a disabled one — caching the answer until the CA's
  `Retry-After` (or `direct.ari_poll_interval` when it gives none; the cached
  answer's `RetryAfter` counts down). A provider without ARI, or one that no
  longer knows the certificate, gets a **synthesized window**: it opens at
  `direct.renew_fraction` of the lifetime and closes where the emergency
  window begins. A provider that is down returns its error (the ACME server
  answers `503`). A certificate the broker did not issue, or whose provider
  is no longer configured, is `ErrNotFound`.
- **`replaces`** is decided per candidate provider. The client's value is
  used when it names a certificate the broker obtained *from that provider*
  that is unreplaced, unexpired and shares a name with the order; otherwise
  it is ignored (never rejected) and the newest unreplaced certificate of the
  lineage from that provider is inferred. A predecessor from an earlier
  upstream account is not named (the CA would refuse it). A provider without
  ARI gets no `replaces`.
- **ARI-qualified** requires the provider's `ARIExempt` and `now` inside the
  predecessor's suggested window (fetched through the same cache). Only then
  is the order admitted as class 1 without budget; outside the window
  `replaces` is still sent but the order is an ordinary renewal with
  ordinary budget.
- **`alreadyReplaced`** from the CA (the predecessor already has a live
  replacement order, for example another account's abandoned order): the
  engine refunds the ARI admission, acquires again as an ordinary renewal
  (reserving the ordinary budgets, new-order budget included), and calls
  `NewOrder` once more without `replaces`. The order row keeps the class and
  `ARIQualified` it was *admitted* with; the budget events tell the truth.
- **Adoption.** Before asking the scheduler, the engine expires overdue
  orders and looks for an adoptable one: an invalid order of the same set and
  provider whose upstream order was prepared, never finalized, not yet
  adopted, and not about to expire. Admission is then asked with
  `ReuseUpstreamOrder` (no new-order budget) and the new order is created
  with `CreateAdopting`, which hands over the URL atomically; a concurrent
  adopter loses with `ErrConflict`, refunds, and asks again without
  adoption. The adopted order is verified in the background (`GetOrder`; a
  pending authorization is validated as usual). It counts as ARI-qualified
  only when the donor's `replaces` is the one the new order would have sent.

## Recovery

`Recover` runs once at startup, before any front end serves, over every
order in status `ready` or `processing` (architecture §20). Reservations are
reattached by order ID; an ARI-qualified admission has none, which is fine.

| Persisted state | Action |
|---|---|
| `Prep intent` (no upstream URL), either mode | `Ticket.OrderCreated` then `Refund` (new-order budget counted as spent, certificate budgets returned); order `invalid`, `Prep failed`. The upstream call may have happened; another is never made. |
| `Mode direct`, upstream URL known, `ready` | `invalid`, refunded, TXT values removed. The requester's key context is gone; direct mode issues again when asked. `Prep prepared` is kept, so the upstream order is adoptable. |
| `Mode direct`, `processing` (CSR recorded) | background `GetOrder`. CA has the CSR (`processing`/`valid`): finish like an ACME order — `Finalize` (idempotent), `WaitCertificate`, `Complete`, `Commit`; the certificate is real, so its budget is spent and it becomes the lineage's predecessor for `replaces`, although the direct cache (whose key died with the process) issues again on the next fetch. CA never received it: `invalid`, refunded. CA unreachable: `invalid` with the certificate budget committed (over-counting is the safe error). |
| `acme`, `Prep preparing` | background `GetOrder` → validate whatever is still pending (`Present` is idempotent per owner/record/value, so a half-published value is picked up) → `prepared`; continues into finalize if a CSR was recorded. |
| `acme`, `Prep prepared`, `processing` (CSR recorded) | background `Finalize` (safe to repeat for the same CSR) → `WaitCertificate` → verify → `Complete`, `Commit`. |
| `acme`, `Prep prepared`, `ready` | nothing; an in-memory job is registered so `Finalize` can proceed, and `Sweep` expires it on time. |
| `valid`, `invalid` | nothing. |
| reservation without a live order | `Commit` if the order is `valid`, else `Refund`. |

Shutdown is the mirror image: `Close(ctx)` waits for background work; when
`ctx` ends first it cancels the background context, and work interrupted
that way is **left in its persisted state** (not failed) for the next
`Recover`. A context error that is *not* a shutdown — a direct client that
hung up before its CSR was sent, or `prepare_timeout` — fails and refunds the
order.

`Sweep` (called by the app about once a minute):

1. expires `ready` orders past `ExpiresAt`: refund, remove their TXT values,
   wake a waiting `Finalize`, audit; a prepared one stays adoptable. This
   step also runs at every admission, so a freshly expired order is seen by
   adoption without waiting for the next sweep;
2. deletes finished orders unchanged for `KeepFinishedOrders` (7 days)
   unless they are the donor of a live adopting order;
3. drops the PEM chain of certificates expired for more than
   `KeepExpiredChains` (30 days); metadata is kept forever.

A preparation that finishes after its order was expired finds `SetPrepared`
refused, refunds (idempotently) and stops; the upstream order is lost to
adoption in that case, which only happens when preparation outlives the
order TTL.

## Audit events

| Type | When |
|---|---|
| `order` allow | admitted: decision reason, grant, provider, class, renewal / ARI / emergency / adoption in `detail` |
| `order` failed | expired without a CSR |
| `order` denied | no provider admitted the request (`rate_limited` or `provider_unavailable`, `Retry-After` in `detail`) |
| `provider_failover` | a fallback provider was chosen: new-issuance fallback, emergency switch, or lineage provider no longer enabled |
| `issue` ok | certificate stored: expiry, certificate ID, serial, predecessor |
| `issue` failed | preparation or finalize failed, or recovery had to fail the order; the stored problem in `detail` |
| `gate` deny | `Finalize` from an address the gate refuses |

Every type but `provider_failover` is part of the activity log that users who
are not admins see, without `detail` (`docs/observability.md`).

Grant attribution comes from the decision that admitted the order and is
carried on every event of that order; DNS-gated orders have none.

## Knobs

| Knob | Default | Used for |
|---|---|---|
| `scheduler.admit_wait` | 20 s | longest wait for a slot in `Admit` / `Issue` |
| `scheduler.finalize_wait` | 20 s | how long `Finalize` holds before answering `processing` |
| `scheduler.order_ttl` | 15 min | life of an order without a CSR |
| `scheduler.down_retry_after` | 1 min | `Retry-After` when no provider is enabled at all |
| `upstream.prepare_timeout` | 10 min | bound of one background step (preparation; finalize) |
| `emergency.fraction`, `emergency.safety_checks`, `emergency.default_interval` | 0.05, 3, 24 h | emergency window |
| `direct.renew_fraction` | 2/3 | start of a synthesized renewal window |
| `direct.ari_poll_interval` | 6 h | cache life of renewal information when the CA gives no `Retry-After` |
| `providers[].ari`, `providers[].ari_exempt` | per provider | whether `replaces` is sent; whether a renewal can be ARI-qualified |
| `KeepFinishedOrders`, `KeepExpiredChains` (constants) | 7 d, 30 d | `Sweep` compaction |

## Wiring

```go
eng, err := issuance.New(issuance.Options{
    Config: cfgSource, Clock: clock,
    Orders: st.Orders(), Certs: st.Certificates(), Lineages: st.Lineages(),
    Providers: registry, DNS: dnsEngine, Scheduler: scheduler, Gate: gate,
    Auditor: auditor, Logger: logger,
})
// startup, after DNSEngine.Reconcile and before serving:
err = eng.Recover(ctx)
// housekeeping, about once a minute:
err = eng.Sweep(ctx)
// shutdown, with the server's grace period:
err = eng.Close(ctx)
```

The tests (`internal/issuance/*_test.go`) run the engine against the real
SQLite store and the real scheduler with the `coretest` fakes for CAs,
Route53, resolver, gate and clock; they cover every engine-owned scenario of
architecture §25 including restarts in each §20 state.
