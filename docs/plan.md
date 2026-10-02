# Implementation plan

`architecture.md` says what the system does. This file says how the code is
cut into packages, what each package promises the others, and in what order
they are built. Keep it current: when a contract changes, change it here in the
same commit.

## Stack

- Go (latest stable), module `tls-broker`, one binary `cmd/tls-broker`.
- SQLite through `modernc.org/sqlite` (no cgo in the shipped binary).
- Downstream ACME server: own handlers on `net/http` + `go-jose/v4` for JWS.
- Upstream ACME client: `go-acme/lego/v4` low-level `acme/api` package (step
  control over order, challenge, finalize; ARI and EAB support).
- Route53: `aws-sdk-go-v2`. LDAP: `go-ldap/ldap/v3`. DNS wire format:
  `miekg/dns`. Metrics: `prometheus/client_golang`. Config: `gopkg.in/yaml.v3`.
- UI: server-rendered `html/template`, embedded assets, no JS build step.
- Everything builds and tests in docker (`scripts/dev`, `Makefile`).

## Package layout

```text
cmd/tls-broker/        main: flags/env, start app
internal/core/         domain types, ports (interfaces), errors, clock
internal/core/coretest fakes for every port: clock, resolver, provider (fake CA),
                       DNS engine, LDAP, auditor
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

`core` holds the vocabulary every package shares. The skeleton step writes it
in full; the sketch below fixes the shape.

Domain types:

- `User{ID, Username, Role, Blocked, Local}`; `Role` = normal | wildcard_allowed | admin.
- `Grant{ID, OwnerUserID, Prefix netip.Prefix, Enabled, Wildcard, CreatedAt, Note}`.
- `Session`, `ACMEAccount{ID, JWK, Thumbprint, Status, Contact}`.
- `Order` (downstream): ID, AccountID, `names.Set`, Replaces, SourceIP,
  State (`ready`, `processing`, `valid`, `invalid`), prep state
  (`intent`, `preparing`, `prepared`, `failed`), Provider, UpstreamOrderURL,
  CSRHash, CertificateID, Class, ExpiresAt, Error.
- `Certificate{ID, names.Set, Provider, AccountURL, Serial, ARICertID, NotBefore,
  NotAfter, ChainPEM, ReplacesID, ReplacedByID, Mode}` — ACME-mode chains are
  stored here; direct-mode key material lives on disk only.
- `Lineage{Key, LastRequestAt, ObservedInterval, Samples}` keyed by `names.Set`.
- `Challenge{ID, ZoneID, RecordName, Value, Owner, State, CreatedAt}`.
- `DirectEntry{Identifier, Generation, NotAfter, RenewAt, LastFetchAt, ...}`.
- `ProviderState{Name, RetryAfter, Circuit, LastError}`; budget events.
- `Decision{Allowed, Reason, GrantID}` with the reason strings of architecture §14.
- `AuditEvent` with the fields of architecture §14.

Ports:

```go
type Clock interface { Now() time.Time; After(d time.Duration) <-chan time.Time }

type Resolver interface {            // public DNS view (DoH)
    LookupA(ctx, name string) ([]netip.Addr, error)   // follows CNAMEs
    LookupTXT(ctx, name string) ([]string, error)
    LookupCAA(ctx, name string) ([]CAA, error)        // RRset at that node only
}

type Gate interface {
    // Mode is acme | direct | dnsproxy. Returns one decision for the whole set.
    Authorize(ctx, mode Mode, src netip.Addr, set names.Set) (Decision, error)
}

type Provider interface {            // one upstream CA account
    Name() string
    Caps() ProviderCaps              // ARI, ARI exemption, CAA issuer, accounturi honoured
    AccountURL(ctx) (string, error)  // registers on first use
    NewOrder(ctx, names []string, replaces string) (UpstreamOrder, error)
    GetOrder(ctx, url string) (UpstreamOrder, error)
    DNSChallenges(ctx, order UpstreamOrder) ([]UpstreamChallenge, error)
    Accept(ctx, ch UpstreamChallenge) error
    WaitReady(ctx, orderURL string) (UpstreamOrder, error)
    Finalize(ctx, order UpstreamOrder, csrDER []byte) (UpstreamOrder, error)
    WaitCertificate(ctx, orderURL string) (chainPEM []byte, err error)
    RenewalInfo(ctx, ariCertID string) (RenewalInfo, error)
}
// Provider errors are *ProviderError{Kind: RateLimited|Busy|Down|Rejected, RetryAfter, Problem}.

type DNSEngine interface {           // Route53 DNS-01
    Present(ctx, owner, fqdn, value string) (challengeID string, err error) // returns once publicly visible
    Cleanup(ctx, challengeID string) error                                  // idempotent
    Reconcile(ctx) error                                                    // after restart
}

type Scheduler interface {
    // Blocks until admitted, ctx done, or refused (*AdmissionError{Kind, RetryAfter}).
    Acquire(ctx, req AdmissionRequest) (Ticket, error)
    ReportProvider(provider string, err error)     // feeds circuits from provider errors
    Snapshot() SchedulerSnapshot                   // for UI and metrics
}
type Ticket interface {
    PrepDone()        // releases the concurrency slot
    Commit()          // certificate issued: budgets consumed
    Refund()          // nothing issued: reservation returned
}

type Issuer interface {              // implemented by internal/issuance
    // ACME proxy path.
    Admit(ctx, AdmitRequest) (*Order, error)            // slot + persisted order + starts preparation
    Finalize(ctx, orderID string, csrDER []byte, src netip.Addr) (*Order, error)
    // Direct path: admission, order, DNS-01, finalize in one call.
    Issue(ctx, IssueRequest) (*Certificate, chainPEM []byte, err error)
    RenewalInfo(ctx, ariCertID string) (RenewalInfo, error)
    Recover(ctx) error
}

type Auditor interface { Record(ctx, AuditEvent) }
type Authenticator interface { Login(ctx, username, password string) (*User, error) }
type Directory interface { Authenticate(ctx, username, password string) error } // LDAP
```

Stores are small per-entity interfaces in `core` (`UserStore`, `GrantStore`,
`SessionStore`, `AccountStore`, `OrderStore`, `CertificateStore`,
`LineageStore`, `ChallengeStore`, `DirectStore`, `ProviderStateStore`,
`BudgetStore`), all implemented by `internal/store`. Front-end and engine tests
use the real SQLite store on a temp file, not a fake.

## Behaviour notes that are easy to get wrong

- **Admission wait points.** `newOrder` holds for a slot (default 20 s),
  `finalize` holds for preparation (default 20 s) and otherwise answers
  `processing`. Budget exhaustion and closed circuits refuse at once.
- **Crash safety.** Order row with upstream intent is committed before
  `Provider.NewOrder`; the URL is committed right after. Recovery follows
  architecture §20 exactly.
- **Same-CSR retry** returns existing state; a different CSR is rejected with
  `orderNotReady`/`malformed` and never reaches upstream.
- **`replaces`.** Taken from the downstream order when present; otherwise the
  engine infers it from the newest unreplaced certificate of the same lineage
  and provider. The exemption rules per provider live in `ProviderCaps`.
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
