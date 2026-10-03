# Implementation plan

`architecture.md` says what the system does. This file says how the code is
cut into packages, what each package promises the others, and in what order
they are built. Keep it current: when a contract changes, change it here in the
same commit.

## Stack

- Go (latest stable), module `tls-broker`, one service binary
  `cmd/tls-broker` (plus the development-only DoH mock `cmd/mockdoh`).
- SQLite through `modernc.org/sqlite` (no cgo in the shipped binary).
- Downstream ACME server: own handlers on `net/http` + `go-jose/v4` for JWS.
- Upstream ACME client: `go-acme/lego/v5` low-level `acme/api` package (step
  control over order with `replaces` and profile, authorization, challenge,
  finalize, certificate, renewal info; EAB support).
- Route53: `aws-sdk-go-v2`. LDAP: `go-ldap/ldap/v3`. DNS wire format:
  `miekg/dns`. Metrics: `prometheus/client_golang`. Config: `gopkg.in/yaml.v3`.
- UI: server-rendered `html/template`, embedded assets, no JS build step.
- Everything builds and tests in docker (`scripts/dev`, `Makefile`).

## Package layout

```text
cmd/tls-broker/        main: env, serve, maintenance subcommands
cmd/mockdoh/           development-only DoH mock for the DNS gate
internal/core/         domain types, ports (interfaces), errors, clock
internal/core/coretest fakes for every non-store port: clock, resolver, provider
                       (fake CA), DNS engine, LDAP, auditor, gate, scheduler,
                       provider registry, config source, secrets; key/CSR helpers
internal/names/        identifier normalization, identifier sets, zone matching
internal/config/       YAML model, validation, generations, secrets, env settings
internal/store/        SQLite: migrations and repositories (implements core stores)
internal/audit/        JSONL audit writer with rotation, reader for the UI
internal/doh/          DoH resolver: A with CNAME chase, TXT, CAA
internal/gate/         authorization decisions for all three modes
internal/sched/        admission scheduler: slots, budgets, provider circuits
internal/dns01/        Route53 DNS-01 engine, in-memory Route53 fake
internal/upstream/     ACME provider adapter (lego), provider registry
internal/issuance/     orchestration: prepare, finalize, one-shot, recovery,
                       provider choice, lineage tracking, emergency window, ARI
internal/acmesrv/      downstream ACMEv2 server
internal/direct/       direct certificate cache and API
internal/dnsproxy/     /dns/present and /dns/cleanup
internal/auth/         LDAP login, local admin, sessions, CSRF
internal/ui/           web UI
internal/httpx/        real source IP, middleware, problem responses
internal/metrics/      Prometheus collectors
internal/app/          wiring, lifecycle, config reload, startup reconciliation
internal/version/      build info set by ldflags
test/e2e/              in-process end-to-end tests on fakes; Pebble-backed tests
test/compat/           scripts running real certbot / acme.sh against the broker
deploy/                Dockerfile, compose.yaml, .env.example, nginx example
docs/                  operator, API and development documentation
```

Dependency rule: packages depend on `core` and `names`, not on each other,
except `issuance` (uses the ports), the three front ends and `ui` (use
`issuance`/`gate` through interfaces declared in `core`), and `app` (wires
concrete types). No package imports `app`.

## Contracts (`internal/core`)

`core` holds the vocabulary every package shares. The Go doc comments in
`internal/core` are the precise contract (idempotency, errors, time, state
preconditions); this section is the map. Files: `doc.go` (conventions),
`types.go`, `ports.go`, `stores.go`, `config.go`, `errors.go`, `problem.go`,
`clock.go`.

Conventions (from `core/doc.go`):

- Stores never read the clock; time-dependent methods take `now`. Everything
  else takes time from `core.Clock`.
- "Not found" is an error matching `core.ErrNotFound`; a broken uniqueness or
  state precondition is `core.ErrConflict` and changes nothing.
- Each store method is one transaction. There is no cross-method transaction;
  flows are ordered so a crash between two methods leaves a state recovery
  understands.
- Orders, certificates, accounts and challenges have caller-chosen string IDs
  (`core.NewID()`); users and grants have store-assigned `int64` IDs.

Domain types:

- `User{ID, Username, Role, Blocked, Local, CreatedAt, LastLoginAt}`; `Role` =
  normal | wildcard_allowed | admin (`AtLeast`, `User.Can`). `(Username, Local)`
  is unique.
- `Grant{ID, OwnerUserID, Prefix netip.Prefix, Enabled, Wildcard, Note, CreatedAt}`.
- `Session{TokenHash, UserID, CSRFToken, SourceIP, CreatedAt, ExpiresAt,
  LastSeenAt}`; cookie token from `NewToken()`, stored as `HashToken(token)`.
- `ACMEAccount{ID, Thumbprint, JWK, Status, Contact, CreatedAt}`.
- `Order`: one issuance attempt, used for both downstream ACME orders
  (`Mode` acme) and direct-mode jobs (`Mode` direct). Fields: ID, Mode,
  AccountID, `names.Set`, Replaces (as sent by the client), SourceIP, GrantID,
  `Status` (`ready`, `processing`, `valid`, `invalid`), `Prep` (`intent`,
  `preparing`, `prepared`, `failed`), Class, ARIQualified, Provider,
  UpstreamOrderURL, UpstreamReplaces, UpstreamExpiresAt, AdoptedByOrderID,
  CSRHash, CSRDER (kept until terminal, for restart), CertificateID,
  `Error *Problem`, CreatedAt, ExpiresAt, UpdatedAt.
- `Certificate{ID, OrderID, Mode, names.Set, Provider, AccountURL, Serial,
  ARICertID, NotBefore, NotAfter, IssuedAt, ChainPEM, ReplacesID, ReplacedByID}`
  — ACME-mode chains are stored; direct-mode key material and chain live on
  disk only. `core.ARICertID(leaf)` computes the RFC 9773 identifier.
- `Lineage{Key, LastRequestAt, ObservedInterval, Samples}` keyed by
  `names.Set.Key()`. `Lineage.Observe(at)` is the one definition of interval
  tracking (requests closer than `MinLineageGap` = 1 h are one visit; later
  gaps move the interval by a quarter). `core.EmergencyWindow(cfg, lifetime,
  interval)` is the formula of architecture §8.
- `Challenge{ID, ZoneID, RecordName, Value, Owner, State, Error, CreatedAt,
  UpdatedAt}`; states of architecture §17 with `Terminal()` and
  `WantsRecord()`; owners built with `OrderOwner(id)` / `DNSProxyOwner(ip)`.
- `DirectEntry{Identifier, Generation, CertificateID, Provider, NotBefore,
  NotAfter, RenewAt, NextARICheckAt, LastFetchAt, LastFetchIP, LastAttemptAt,
  LastError, Failures, CreatedAt, UpdatedAt}`.
- `ProviderState{Name, Health (healthy | rate_limited | down), RetryAfter,
  LastError, Failures, UpdatedAt}`; `BudgetEvent{ID, Ref, Provider, Kind
  (new_order | cert_domain | cert_set), Key, At, State (reserved | committed),
  Renewal}`.
- `Decision{Allowed, Reason, GrantID, Name, Detail}` with the `Reason*`
  constants (architecture §14 plus `wildcard_unprotected`, `dns_mismatch`,
  `dns_failure`, `invalid_identifier`, `not_ipv4`).
- `AuditEvent` with the fields of architecture §14, `Audit*` type constants and
  a `Visibility` (public | admin).
- `PriorityClass` 1–6 as in architecture §10.

Errors:

- Sentinels: `ErrNotFound`, `ErrConflict`, `ErrExpired`, `ErrCSRMismatch`,
  `ErrInvalidCredentials`, `ErrDirectoryUnavailable`, `ErrOutsideManagedZones`,
  `ErrDNSPropagation`, `ErrResolver`.
- `*ProviderError{Provider, Kind, RetryAfter, Problem, Err}`; kinds
  `rate_limited`, `busy`, `down`, `rejected`, `already_replaced`.
- `*AdmissionError{Kind, Provider, RetryAfter, Reason}`; kinds `rate_limited`,
  `provider_busy`, `provider_down`.
- `*Problem` (RFC 7807 + ACME): `Problem*` type constants, `NewProblem`,
  `ProblemStatus`, and `ProblemFromError(err)` which maps every error above to
  what an ACME client should see without leaking internal text.

Ports (signatures abridged; `ctx` is `context.Context`):

```go
type Clock interface { Now() time.Time; After(d time.Duration) <-chan time.Time }
// SystemClock; Sleep(ctx, clock, d)

type Resolver interface {            // public DNS view (DoH); NXDOMAIN = empty, nil
    LookupA(ctx, name string) ([]netip.Addr, error)   // follows CNAMEs
    LookupTXT(ctx, name string) ([]string, error)
    LookupCAA(ctx, name string) ([]CAA, error)        // RRset at that node only
}

type Gate interface {
    // Mode is acme | direct | dnsproxy. One decision for the whole set. A denial
    // (including DNS failure) is a Decision, not an error.
    Authorize(ctx, mode Mode, src netip.Addr, set names.Set) (Decision, error)
}
type CAAChecker interface { CheckCAA(ctx, name string) (CAAStatus, error) } // gate, for the UI

type Provider interface {            // one upstream CA account
    Name() string
    Caps() ProviderCaps              // ARI, ARIExempt, CAAIssuers, AccountURIHonoured
    AccountURL(ctx) (string, error)  // registers on first use
    NewOrder(ctx, names []string, replaces string) (UpstreamOrder, error)
    GetOrder(ctx, orderURL string) (UpstreamOrder, error)
    DNSChallenges(ctx, order UpstreamOrder) ([]UpstreamChallenge, error) // pending authzs only
    Accept(ctx, ch UpstreamChallenge) error
    WaitReady(ctx, orderURL string) (UpstreamOrder, error)
    Finalize(ctx, orderURL string, csrDER []byte) (UpstreamOrder, error) // same CSR again is safe
    WaitCertificate(ctx, orderURL string) (chainPEM []byte, err error)
    RenewalInfo(ctx, ariCertID string) (RenewalInfo, error) // WindowStart/End, ExplanationURL, RetryAfter
}
type Providers interface { Get(name string) (Provider, bool); Enabled() []Provider }

type DNSEngine interface {           // Route53 DNS-01; record = "_acme-challenge.<name>"
    Present(ctx, owner, record, value string) (challengeID string, err error) // idempotent per triple; returns once visible
    Cleanup(ctx, challengeID string) error                                    // idempotent
    CleanupOwner(ctx, owner string) error
    Reconcile(ctx) error                                                      // after restart
}

type Scheduler interface {
    // Blocks until admitted, ctx done, or refused (*AdmissionError).
    Acquire(ctx, req AdmissionRequest) (Ticket, error)
    Reattach(ctx, ref string) (Ticket, error)      // reservation that survived a restart
    OpenRefs(ctx) ([]string, error)
    ReportProvider(ctx, provider string, err error) // feeds circuits; nil = success
    Snapshot() SchedulerSnapshot                    // for UI and metrics
}
// AdmissionRequest{Ref (= Order.ID), Provider, Names, Class, Renewal,
//                  ARIQualified, ReuseUpstreamOrder, MaxWait}
type Ticket interface {
    Ref() string
    OrderCreated()    // call before Provider.NewOrder: new-order budget is spent for good
    PrepDone()        // releases the concurrency slot
    Commit()          // certificate issued: certificate budgets consumed
    Refund()          // nothing issued: certificate budgets returned
}

type Issuer interface {              // implemented by internal/issuance
    Admit(ctx, AdmitRequest) (*Order, error)        // reuse open order, or slot + persisted order + background prep
    Finalize(ctx, FinalizeRequest) (*Order, error)  // idempotent by CSR hash; holds up to FinalizeWait
    Issue(ctx, IssueRequest) (*Certificate, error)  // direct path, synchronous; ChainPEM set
    RenewalInfo(ctx, ariCertID string) (RenewalInfo, error) // also records a lineage observation
    Recover(ctx) error                              // architecture §20, once at startup
    Sweep(ctx) error                                // expire unfinalized orders, compact
}

type Auditor interface { Record(ctx, AuditEvent) }
type AuditReader interface { Query(ctx, AuditQuery) ([]AuditEvent, error) }
type Directory interface { Authenticate(ctx, username, password string) error } // LDAP
type LDAPTester interface { TestLDAP(ctx, LDAPConfig) error }
type Authenticator interface {       // implemented by internal/auth, used by ui
    Login(ctx, username, password string, src netip.Addr) (*Login, error)
    Session(ctx, token string) (*Session, *User, error)
    Logout(ctx, token string) error
}

type ConfigSource interface { Current() *Config; Subscribe() (<-chan struct{}, func()) }
type ConfigAdmin interface { Generations; Read; Validate; Activate; Rollback } // config, used by ui
type SecretStore interface { Get; Put; Delete; List }                          // <data>/secrets
```

Front ends call `Gate.Authorize` themselves and pass the `Decision` to the
`Issuer`; the gate does not write audit records, its callers do.

Configuration view (`core/config.go`): `Config{Generation, DataDir, Server,
Bootstrap, Zones, Route53, Providers, LDAP, Sessions, Scheduler, Emergency,
Direct, DNSProxy, Upstream, Resolver, Audit}` as plain structs, built only by
`internal/config`. `ProviderConfig{Name, Disabled, DirectoryURL, Contact,
EABKeyID, EABSecretName, Profile, CAAIssuers, AccountURIHonoured, ARI,
ARIExempt, Limits{NewOrders, CertsPerDomain, CertsPerSet, Concurrency,
RenewalReservePercent}}`. `core.DefaultConfig()` and
`core.DefaultProviderLimits()` are the single source of defaults. Helpers:
`ManagedZones()`, `ZoneFor(name)`, `Provider(name)`, `EnabledProviders()`,
`TrustsProxy(peer)`.

Stores (all implemented by `internal/store`; front-end and engine tests use the
real SQLite store on a temp file, not a fake):

| Store | Methods |
|---|---|
| `UserStore` | `Ensure`, `Get`, `GetByUsername`, `List`, `SetRole`, `SetBlocked`, `TouchLogin` |
| `GrantStore` | `Create`, `Get`, `List`, `Update`, `Delete`, `Match(addr)` (enabled grants covering the address; wildcard first, then longest prefix) |
| `SessionStore` | `Create`, `Get`, `Touch`, `Delete`, `DeleteByUser`, `DeleteExpired` |
| `AccountStore` | `Create`, `Get`, `GetByThumbprint`, `Update`, `UpdateKey` |
| `OrderStore` | `Create`, `CreateAdopting`, `Get`, `FindOpen`, `FindAdoptable`, `SetUpstream`, `SetPrepared`, `BeginFinalize`, `Complete`, `Fail`, `ExpireDue`, `ListActive`, `List`, `Prune` |
| `CertificateStore` | `Get`, `GetByARICertID`, `Newest`, `NewestUnreplaced`, `MarkReplaced`, `List`, `DropChains` |
| `LineageStore` | `Get`, `Observe` |
| `ChallengeStore` | `Create`, `Get`, `SetState`, `FindActive`, `ListActive`, `ListByRecord`, `ListByOwner`, `CountCreatedSince`, `ListStale`, `Prune` |
| `DirectStore` | `Get`, `Put`, `TouchFetch`, `List`, `Delete` |
| `ProviderStateStore` | `Get`, `Put`, `List` |
| `BudgetStore` | `Reserve`, `Commit`, `Release`, `ListByRef`, `ListSince`, `ListReserved`, `Prune` |

How the order methods carry the flows:

- **newOrder.** `FindOpen` (reuse) → `ExpireDue` + `FindAdoptable` →
  `Scheduler.Acquire` → `Create` (Prep `intent`) or `CreateAdopting` (Prep
  `prepared`, donor marked `AdoptedByOrderID`). Then, in the background:
  `Ticket.OrderCreated` → `Provider.NewOrder` → `SetUpstream` (Prep
  `preparing`) → DNS-01 → `SetPrepared` → `Ticket.PrepDone`.
- **finalize.** `BeginFinalize` records the CSR exactly once (same hash: returns
  existing state; other hash: `ErrCSRMismatch`; expired: `ErrExpired`) and
  moves Status to `processing`, possibly before preparation has finished. Then
  `Provider.Finalize` → `WaitCertificate` → `Complete` (inserts the
  certificate, marks the predecessor replaced, Status `valid`) →
  `Ticket.Commit`. Failures go through `Fail` → `Ticket.Refund`.
- **Certificates are created only by `OrderStore.Complete`**, for both modes.
- **Expiry.** `ExpireDue` invalidates orders that never got a CSR; a prepared
  one stays adoptable (`Fail` and `ExpireDue` keep Prep `prepared`).
- **Recovery** reads `ListActive` and `Scheduler.OpenRefs`.

Fakes (`internal/core/coretest`): `FakeClock`, `FakeResolver`, `FakeCA`
(`core.Provider`: real X.509 chain, order/authorization state, dns-01 checked
through a pluggable TXT lookup, Boulder's `replaces` rules, ARI windows,
counters, fault injection by operation), `FakeDNSEngine`, `FakeDirectory`,
`FakeAuditor`, `FakeGate`, `FakeScheduler`, `FakeProviders`, `FakeConfig`
(with the `NewConfig()` fixture), `FakeSecrets`, and `GenKey` / `GenRSAKey` /
`MakeCSR` / `ParseChain`.

`internal/names`: `Normalize`, `IsWildcard`, `Base`, `Wildcard`,
`ChallengeRecord`, `IdentifierFromChallengeRecord`, `RegisteredDomain`,
`InZone`; `Set` (`NewSet`, `MustSet`, `ParseKey`, `Key`, `Hash`, `Names`,
`Contains`, `Overlaps`, `HasWildcard`, `Wildcards`, `NonWildcards`,
`ChallengeRecords`, `RegisteredDomains`, text and JSON marshalling); `Zones`
(`NewZones`, `Match`, `Contains`, `FirstOutside`, `List`).

## Behaviour notes that are easy to get wrong

- **Admission wait points.** `newOrder` holds for a slot (default 20 s),
  `finalize` holds for preparation (default 20 s) and otherwise answers
  `processing`. Budget exhaustion and closed circuits refuse at once.
- **Crash safety.** Order row with upstream intent is committed before
  `Provider.NewOrder`; the URL is committed right after. Recovery follows
  architecture §20 exactly.
- **Same-CSR retry** returns existing state; a different CSR is rejected with
  `orderNotReady`/`malformed` and never reaches upstream.
- **`replaces`.** Taken from the downstream order when it matches a certificate
  the broker issued; otherwise the engine infers it from the newest unreplaced
  certificate of the same lineage and provider. ARI-qualified (priority 1,
  budget-exempt) only when `ProviderCaps` says the provider exempts ARI and now
  is inside the suggested window. `alreadyReplaced` from upstream: retry once
  without `replaces`. See architecture §8 "ARI rules".
- **Upstream order adoption.** A prepared, unfinalized upstream order whose
  downstream order expired is reused by the next downstream order for the same
  identifier set and provider.
- **Provider facts (Oct 2026).** Let's Encrypt: new orders 300/3h per account,
  50 certs/7d per registered domain, 5/7d per exact set, all token buckets;
  unfinalized orders cost only the new-order limit; honours CAA `accounturi`;
  profiles `classic`/`tlsserver`/`shortlived` selected by `profile` in newOrder.
  Google Trust Services: directory `https://dv.acme-v02.api.pki.goog/directory`,
  EAB required and single-use (keep the account key), 100 newOrder/hour per
  project, no challenge retry (confirm propagation before accepting), CAA
  `accounturi` support unconfirmed (default off).
- **Client limits.** Certbot: 45 s HTTP timeout, 90 s wait after finalize.
  acme.sh: 30 polls after finalize at `Retry-After` (2 s default).
- **Emergency window** is computed in `issuance` from the lineage's observed
  interval (architecture §8) and decides provider switching and priority class.
- **DNS proxy wildcard protection** is the CAA check of architecture §3.2 and
  lives in `gate`.
- **Direct cache** is request-driven; one `singleflight` group per identifier.
- **Real source IP** comes from `httpx` only: the configured header when the
  TCP peer is a trusted proxy, the TCP peer otherwise.

## Testing layers

1. Unit tests per package on fakes (`coretest`) and temp-file SQLite.
2. `test/e2e` in-process: full broker wired with the fake CA, fake Route53,
   fake resolver, fake LDAP and a fake clock; a Go ACME client plays the
   downstream. Covers every scenario and invariant in architecture §25.
3. `test/e2e` with build tag `pebble`: the real `upstream` adapter against
   Pebble + challtestsrv containers (`make e2e-pebble`).
4. `test/compat`: real certbot (old and current) and acme.sh containers against
   a broker backed by Pebble (`make compat`). Manual / dispatch-only in CI.
5. Let's Encrypt staging and a production canary are run by the operator with
   real credentials; see `docs/development.md`.

## Build order

Each step ends with `make check` green and its code, tests and docs committed
together. Steps inside a wave touch disjoint directories and run in parallel.

| Wave | Step | Owns | Docs |
|---|---|---|---|
| 0 | Skeleton: module, dev tooling, CI, image, compose, `core`, `coretest`, `names`, `version` | repo root, `deploy/`, `.github/`, `internal/{core,names,version}` | `README.md`, `docs/development.md` |
| 1 | Store | `internal/store` | `docs/data-model.md` |
| 1 | Config, generations, secrets | `internal/config` | `docs/configuration.md` |
| 1 | DoH resolver + gate | `internal/{doh,gate}` | `docs/authorization.md` |
| 1 | Scheduler | `internal/sched` | `docs/rate-limits.md` |
| 1 | Route53 DNS-01 engine | `internal/dns01` | `docs/dns01.md` |
| 1 | Upstream ACME provider | `internal/upstream` | `docs/providers.md` |
| 1 | Audit, metrics, httpx | `internal/{audit,metrics,httpx}` | `docs/observability.md` |
| 1 | Auth | `internal/auth` | `docs/authentication.md` |
| 2 | Issuance engine | `internal/issuance` | `docs/issuance.md` |
| 3 | ACME server | `internal/acmesrv` | `docs/acme-proxy.md` |
| 3 | Direct cache + API | `internal/direct` | `docs/direct-api.md` |
| 3 | DNS proxy | `internal/dnsproxy` | `docs/dns-proxy.md` |
| 3 | Web UI | `internal/ui` | `docs/ui.md` |
| 4 | App wiring, main, e2e, compat scripts, deployment and operations docs | `internal/app`, `cmd/`, `test/` | `docs/deployment.md`, `docs/operations.md` |
| 5 | Independent review against architecture §25 invariants, fixes | whole repo | as needed |

Rules while waves run in parallel:

- Touch only the directories your step owns. If a `core` contract is wrong or
  missing something, make the smallest change to `core`, run `make check` for
  the whole repo, and commit it separately with the reason.
- Do not edit `go.mod`/`go.sum`; all dependencies are pinned by the skeleton.
  If one is missing, say so in your report.
- Commit with explicit paths (`git add <paths>; git commit -- <paths>`); never
  `git add -A`. Retry if `index.lock` is held by another agent.
