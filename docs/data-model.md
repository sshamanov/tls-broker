# Data model

All mutable application state lives in one SQLite database,
`<data>/state.db` (architecture §13, §22). Package `internal/store` owns it and
implements every store interface of `internal/core` (`stores.go`) on it. Static
configuration, secrets, certificate key material and the audit log are files,
not rows; see "What is not stored" below.

## Engine and concurrency

- Driver `modernc.org/sqlite` (pure Go, no cgo).
- WAL journal, `synchronous=FULL` (a method that returned is durable, also
  across power loss), `foreign_keys=ON`, `busy_timeout` 10 s.
- **Single writer.** All writes go through a pool of exactly one connection
  and every write transaction starts with `BEGIN IMMEDIATE`. Writers are
  therefore serialized inside the process; a method that reads and then
  writes (all state transitions do) sees no concurrent change in between.
  This is what makes `BeginFinalize`, `CreateAdopting` and `Ensure` safe under
  concurrent goroutines.
- **Readers** use a separate pool of up to 8 `query_only` connections and
  never wait for the writer (WAL snapshot reads).
- **One method, one transaction.** Every store method is exactly one
  transaction, as `core/doc.go` requires. There are no cross-method
  transactions; flows are ordered so a crash between two calls leaves a state
  that recovery understands (architecture §20, see below).
- **Errors.** Missing rows are `core.ErrNotFound`. Uniqueness and state
  violations — including SQLite constraint failures such as a duplicate ID,
  a duplicate ARI identifier or a session for an unknown user — are
  `core.ErrConflict` and change nothing. `BeginFinalize` adds
  `core.ErrCSRMismatch` and `core.ErrExpired`.

### Value encoding

| Go | Column |
|---|---|
| `time.Time` | `INTEGER` Unix nanoseconds, UTC; `0` = zero time. Times outside 1678–2262 are clamped. Values round-trip exactly and come back in UTC. |
| `bool` | `INTEGER` 0/1 |
| absent string | `''`, never `NULL` (keeps equality tests and partial indexes simple) |
| `names.Set` | `set_key` = `Set.Key()` (normalized names joined by `,`) |
| `netip.Addr` | text, `''` when unset |
| `netip.Prefix` (grants) | masked CIDR text plus `net_start`/`net_end`/`bits` integers |
| `*core.Problem` | JSON problem document, `''` when nil |
| `time.Duration` | `INTEGER` nanoseconds |

## Schema and migrations

Migrations are embedded SQL files, `internal/store/migrations/NNNN_name.sql`,
numbered 1, 2, 3, … without gaps. `Open` applies every pending migration, each
in its own transaction together with the `PRAGMA user_version` bump, so a crash
leaves the database at a whole version. Migrations are forward-only: there are
no down migrations, and `Open` refuses a database whose `user_version` is newer
than the binary knows (a downgrade would otherwise silently misread it). Change
the schema only by adding a new file; never edit a released one.

## Tables

### `users`

Humans of the control plane (architecture §4–5). `id` is assigned by the
store; `(username, local)` is unique, so the local break-glass admin and an
LDAP user of the same name are different rows. Columns: `role`
(`normal | wildcard_allowed | admin`), `blocked`, `created_at`,
`last_login_at`. Users are never deleted.

### `grants`

IP grants: durable capability objects (§4.2). `owner_user_id` is informational
and deliberately **not** a foreign key — a grant's effect never depends on its
owner. The prefix is stored masked; `net_start`/`net_end` (first and last
address as integers) and `bits` make `Match` a range query ordered
`wildcard DESC, bits DESC, id`. Only IPv4 prefixes are accepted, and only IPv4
addresses match (an IPv4-mapped IPv6 address matches nothing).

### `sessions`

UI sessions keyed by `token_hash` = `core.HashToken(cookie token)`; the token
itself is never stored. `user_id` references `users` (`ON DELETE CASCADE`).
Holds the per-session CSRF token, source IP, `created_at`, `expires_at`,
`last_seen_at`. `Get` returns expired sessions too; the caller compares.
`DeleteExpired(now)` removes `expires_at <= now`.

### `acme_accounts`

Downstream ACME accounts: protocol state only (§6). `thumbprint` (RFC 7638) is
unique; `jwk` is the public key; `contact` is a JSON array. `UpdateKey`
(keyChange) swaps key and thumbprint, `ErrConflict` if another account has the
new thumbprint.

### `orders`

One row per issuance attempt: downstream ACME orders (`mode = 'acme'`) and
direct-mode jobs (`mode = 'direct'`). Each maps to at most one upstream order,
ever. Key columns:

| Column | Meaning |
|---|---|
| `status` | `ready → processing → valid`, or `→ invalid` (what the ACME client sees) |
| `prep` | `intent → preparing → prepared`, or `→ failed` (upstream preparation) |
| `provider` | chosen at admission, never changes |
| `upstream_order_url`, `upstream_replaces`, `upstream_expires_at` | the upstream order |
| `adopted_by_order_id` | set on a dead order whose upstream order was taken over |
| `csr_hash`, `csr_der` | finalize idempotency key, and the CSR kept only until terminal |
| `certificate_id` | references `certificates`; set only by `Complete` |
| `error` | problem document of an invalid order |
| `class`, `ari_qualified`, `replaces`, `grant_id`, `source_ip`, `account_id` | admission facts (`account_id` is not a foreign key; direct orders have none) |

Constraints enforced by the schema itself:

- `orders_upstream_owner`: unique `upstream_order_url` among rows with
  `adopted_by_order_id = ''`. **An upstream order has at most one owning
  order**, whatever the code does.
- `csr_der` is `NULL` unless `status` is `ready`/`processing`.
- `status = 'valid'` requires `certificate_id`.

State machine (who may change what):

```text
Create            status=ready      prep=intent
SetUpstream                         intent -> preparing (URL recorded)   [status ready|processing]
SetPrepared                         preparing -> prepared                [prepared again: no-op]
BeginFinalize     ready -> processing                CSR recorded once  [may precede SetUpstream/SetPrepared]
Complete          processing -> valid                certificate row + replaced-by link, CSR dropped
Fail              ready|processing -> invalid        prep -> failed unless prepared, CSR dropped
ExpireDue         ready (expires_at <= now) -> invalid, like Fail, problem "malformed: order expired"
CreateAdopting    new order: status=ready prep=prepared with the donor's upstream order;
                  donor: adopted_by_order_id = new id
```

`BeginFinalize` decides, in one transaction: same CSR hash already recorded →
existing state, `first=false`; different hash → `ErrCSRMismatch`; invalid
without CSR → existing state, `first=false`; ready but `expires_at <= now` →
`ErrExpired` (nothing changes; `ExpireDue` does the expiry); otherwise record
the CSR and move to `processing`, `first=true`. Under concurrent calls exactly
one caller gets `first=true`.

**Adoption.** An order is adoptable when `status = invalid`, no CSR, `prep =
prepared`, `upstream_order_url` set and not yet adopted: its client vanished
after the upstream order was validated. `FindAdoptable(provider, setKey, now)`
returns the newest such order whose upstream order is usable for at least
another hour. `CreateAdopting` re-checks every condition, plus same provider
and same identifier set, in the same transaction that marks the donor and
inserts the adopter; of any number of concurrent adopters exactly one wins,
the others get `ErrConflict` and nothing changes. An adopter that itself
expires unfinalized becomes adoptable in turn.

**Compaction.** The CSR is dropped when an order becomes terminal; problem
documents are small. `Prune(before)` deletes terminal orders last changed
before `before`, except a donor whose adopter is still active. Certificates are
never deleted with their order.

### `certificates`

The ARI / renewal mapping of architecture §8: one row per certificate the
broker obtained, inserted only by `OrderStore.Complete` in the same
transaction that makes the order valid. Columns: `order_id` (not a foreign
key — orders are pruned, certificates are kept), `mode`, `set_key`,
`provider`, `account_url` (upstream account), `serial`, `ari_cert_id` (RFC 9773;
unique when non-empty), `not_before`, `not_after`, `issued_at`, `chain_pem`,
`replaces_id`, `replaced_by_id`.

- `chain_pem` is stored for ACME-mode certificates only (the downstream client
  fetches it from here). It is `NULL` for direct-mode certificates, whose files
  on disk are the truth, and after `DropChains(before)` clears expired chains.
  Metadata rows are kept forever.
- Replacement links: `Complete` sets the predecessor's `replaced_by_id` when
  `replaces_id` names a certificate that has none yet; `MarkReplaced` does the
  same on its own. An existing link is never overwritten, and an unknown
  predecessor is ignored. `replaces_id`/`replaced_by_id` are not foreign keys.
- `NewestUnreplaced(setKey, provider, now)` — latest `not_before` without
  `replaced_by_id` and with `not_after > now` — is the predecessor named in an
  upstream `replaces`.

### `lineages`

Per identifier-set key: `last_request_at`, `observed_interval`, `samples`.
`Observe` applies `core.Lineage.Observe` atomically (read, compute, upsert in
one write transaction), so concurrent observations are never lost.

### `challenges`

DNS-01 TXT values (architecture §17): `zone_id`, `record_name`, `value`,
`owner` (`order:<id>` or `dnsproxy:<ip>`), `state`, `error`, `created_at`,
`updated_at`.

```text
pending -> presenting -> waiting_dns -> ready -> cleaning -> done
                any non-terminal state -> any state; done, failed are terminal
```

Leaving a terminal state is `ErrConflict`; setting a terminal state again is a
no-op. The reconcile queries all read only non-terminal rows: `ListActive`
(restart: the desired RRsets are the values whose state `WantsRecord`),
`ListByRecord(zone, record)` (rebuild one RRset), `ListByOwner`,
`FindActive(owner, record, value)` (idempotent present) and
`ListStale(before)` (abandoned values). `CountCreatedSince(owner, since)`
counts rows in every state, for DNS-proxy rate limiting. `Prune(before)`
deletes terminal rows last changed before `before`.

### `direct_entries`

Direct-cache metadata, one row per identifier (architecture §11–12): active
`generation` number, `certificate_id`, `provider`, validity, `renew_at`,
`next_ari_check_at`, last fetch (`last_fetch_at`, `last_fetch_ip` — changed
only by `TouchFetch` once the row exists), last attempt, `last_error`,
`failures`. `Put` upserts and keeps the original `created_at`.

### `provider_states`

Persisted provider circuit (architecture §20 "Provider state"): `health`
(`healthy | rate_limited | down`), `retry_after`, `last_error`, `failures`.

### `budget_events`

The scheduler's sliding-window budgets (architecture §10, `docs/rate-limits.md`).
One row per unit of one budget: `ref` (the order ID), `provider`, `kind`
(`new_order | cert_domain | cert_set`), `key` (registered domain or set key),
`at`, `state`, `renewal`.

```text
Reserve -> reserved --Commit--> committed --Prune (at < before)--> deleted
              \--Release--> deleted
```

Both states count while `at` is inside the window. `Reserve` inserts all events
of one admission atomically; `Release` never deletes committed events;
`Prune` never deletes reserved ones. `ListSince(since)` (`at >= since`) is what
the scheduler loads at startup; `ListReserved` lists reservations of any age so
recovery can reattach or refund them.

## Crash recovery (architecture §20)

Because every transition is one durable transaction, a restart finds each
order in exactly one of these shapes, all returned by `ListActive`:

| Found after restart | Meaning | What recovery does with the store |
|---|---|---|
| `ready`/`processing`, `prep = intent`, no URL | upstream call may or may not have happened | `Fail`; `SetUpstream` is refused from then on, so no second upstream order |
| `prep = preparing`, URL set | upstream order exists | query it, finish DNS-01, `SetPrepared` |
| `processing`, CSR kept | CSR recorded, maybe sent | query upstream, `Complete` or `Fail`; same-CSR finalize retries return this state |
| `valid` | done | served from `certificates` |
| `invalid` | done | stays failed (adoptable if prepared and never finalized) |

Budget reservations survive in `budget_events` (`ListReserved`); challenge
rows that are not terminal drive DNS reconciliation.

## What is not stored

- **No private keys, ever.** Direct-mode keys and chains live in generation
  directories under `<data>/certs/` (architecture §12); downstream ACME
  clients keep their own keys; upstream account keys and EAB secrets are under
  `<data>/secrets/`. A test scans every column of every table for PEM private
  key markers.
- No direct-mode certificate chains (the files on disk are the truth).
- No session tokens (only their SHA-256), no LDAP passwords, no secrets.
- No configuration: zones, providers, LDAP settings and limits are YAML
  generations under `<data>/config/` (architecture §15).
- No audit history: that is the JSONL log under `<data>/audit/` (§14).
- No work queues or locks: in-flight work is reconstructed from order,
  challenge and budget rows.
- No bulky protocol bodies after completion: CSRs are dropped at terminal
  states, expired chains by `DropChains`, old orders and challenges by `Prune`.

## Backup

`Store.Backup(ctx, dest)` writes a consistent snapshot with `VACUUM INTO`
(architecture §23) on a dedicated connection: one read transaction on the
live database, so writers are not blocked and the copy is transactionally
consistent. `dest` must not exist; the result is a compacted, self-contained
database file without WAL that `Open` accepts as it is. Never copy `state.db`
with plain file tools while the broker runs — the WAL file holds committed
transactions that the main file may not contain yet.

To restore, stop the broker, put the snapshot in place as `<data>/state.db`
(remove any stale `state.db-wal` / `state.db-shm`), and start it; startup
reconciliation repairs orders, challenges and cache metadata (architecture
§23).
