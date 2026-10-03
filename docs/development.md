# Development

Go is not needed on the host. Every build and test runs in the `golang`
container through `scripts/dev`; `make` targets wrap the common cases.

## Commands

| Command | What it does |
|---|---|
| `make check` | gofmt check, `go vet ./...`, `go test -race ./...` (including the in-process end-to-end suite). Must be green before every commit. |
| `make test` | `go test ./...` without the race detector (faster). |
| `make fmt` | `gofmt -w` on the source tree. |
| `make build` | Static binaries `bin/tls-broker` and `bin/mockdoh`. |
| `make image` | Container image `tls-broker:local` from `deploy/Dockerfile` (both binaries). |
| `make run-test` | `docker compose -f deploy/compose.test.yaml up -d`: the local test deployment with live credentials (see `docs/deployment.md`). |
| `make e2e` | Only the in-process end-to-end tests (`test/e2e`), uncached. |
| `make e2e-pebble` | The broker with the real upstream adapter against Pebble and challtestsrv containers (`test/pebble.sh`). |
| `make compat` | Real certbot (current, Ubuntu 20.04, 0.31) and acme.sh against the broker image backed by Pebble (`test/compat/run.sh`). |
| `make clean` | Removes `bin/` and `.cache/`. |

`scripts/dev <cmd...>` runs any command in the container, for example:

```sh
scripts/dev go test -race ./internal/names/...          # one package
scripts/dev go test -race -run TestSetKey ./internal/names/
scripts/dev go vet ./internal/core/...
scripts/dev sh                                          # interactive shell
```

How the container is run: plain `docker run --rm --network host`, the
repository mounted at `/src`, the process running as your uid:gid so files it
creates belong to you. The Go build and module caches are in `.cache/`
(gitignored), so the first run downloads modules and later runs are fast.
`GO_IMAGE` overrides the image (default `golang:1.27`). Compose is only used
for shipping (`deploy/compose.yaml`).

## Layout

`docs/plan.md` has the full package list and the dependency rule. In short:

- `cmd/tls-broker` — the binary.
- `internal/core` — shared domain types, port interfaces, store interfaces,
  errors, configuration view. Every other package compiles against it.
- `internal/core/coretest` — fakes for the ports: clock, resolver, fake CA,
  DNS engine, LDAP directory, auditor, gate, scheduler, provider registry,
  config source, secrets; key and CSR helpers.
- `internal/names` — identifier normalization, identifier sets, zone matching.
- `internal/<pkg>` — one package per subsystem, depending on `core` and
  `names` rather than on each other.
- `internal/app` — wiring, startup recovery, HTTP mounts, housekeeping,
  shutdown, and the helpers behind the maintenance subcommands.
- `deploy/` — Dockerfile, compose files, `.env.example`, reverse-proxy
  examples.

## Testing layers

1. **Unit tests** per package, on the `coretest` fakes and a temp-file SQLite
   store (`t.TempDir()`). No network, no real time: take time from
   `core.Clock` and drive it with `coretest.FakeClock`.
2. **In-process end-to-end** (`test/e2e`, part of `make check`; `make e2e`
   runs only it): the whole broker wired with the fake CAs, fake Route53,
   fake resolver, fake LDAP and fake clock (below).
3. **Pebble** (`make e2e-pebble`): the same suite's harness with the real
   upstream adapter against Pebble and challtestsrv containers (below).
4. **Compatibility** (`make compat`): real certbot and acme.sh containers.
5. **Let's Encrypt staging and a production canary** are run by the operator
   with real credentials; they are not automated here.

Layers 3 and 4 run in CI only on manual dispatch (`.github/workflows/e2e.yml`);
`.github/workflows/ci.yml` runs `make check`, so layers 1 and 2 gate every
push.

Rules that keep tests trustworthy:

- Every external dependency is reached through an interface in `core` and has a
  fake. A new external call brings its fake in the same change.
- Do not skip a failing test or weaken an assertion to get green.
- Scratch files go in `.claude/tmp/` or `t.TempDir()`, never the system temp
  directory.

### In-process end-to-end suite (`test/e2e`)

Each scenario boots its own broker through `internal/app` on a temporary data
directory and talks to it only over HTTP, the way clients do:

- **World.** Two managed zones (`example.com`, `example.org`) in
  `dns01.FakeRoute53`; two `coretest.FakeCA`s behind `NewFakeProviders`: the
  primary `letsencrypt` (ARI exempt) and the fallback `google` (ARI, not
  exempt), both validating DNS-01 against Route53's public view
  (`SetTXTLookup(r53.LookupTXT)`); the DNS gate's A and CAA answers from a
  `coretest.FakeResolver`; LDAP users from `coretest.FakeDirectory`; one
  `coretest.FakeClock` for everything. The YAML is activated through the
  app's configuration store, as the UI would.
- **Front.** An `httptest` TLS server in front of `App.Handler()` (lego
  requires https). It outlives the app, so a restart on the same data
  directory keeps every URL. Each "machine" is an HTTP client whose requests
  carry its address in `X-Real-IP`, trusted from 127.0.0.1.
- **Clients.** lego's low-level `acme/api` for the ACME proxy, plain
  `net/http` for `/cert/` and `/dns/`, a cookie-jar client (with the CSRF
  token) for the UI.
- **Time.** Nothing waits in real time except where the broker's goroutines
  run: code that sleeps on the clock (Route53 polling, slow-CA faults,
  `finalize_wait`) runs under `pump`, which advances the fake clock in small
  steps; days pass with `advance`. Background work is awaited by polling
  broker state (`eventually`), never by fixed sleeps that assume an order.
- **Scenarios.** `TestScenarios` has one parallel subtest per architecture
  §25 scenario, named after it (`new issuance`, `ARI renewal`, `upstream
  429`, `duplicate direct requests collapse to one issuance`, ...), plus
  finalize-before-preparation, a client vanishing after newOrder (expiry,
  refund, adoption), the DNS proxy, the UI and `/healthz` before ready.
  Failures are injected with the fakes' fault hooks (`FakeCA.Inject`,
  `FakeRoute53.Hang`/`SetPublicDelay`).
- **Invariants.** Every scenario ends with `checkInvariants`, which checks
  across everything the broker stored: one downstream order owns at most one
  upstream order and every upstream order at the fake CAs belongs to exactly
  one broker order; no order with an upstream order skipped the scheduler
  (budget events, or ARI-qualified); no wildcard certificate without a
  wildcard grant; a renewal that named its predecessor stayed with the same
  provider and account. The direct-mode invariants (one job per identifier,
  cached certificate served through an outage, expired never served) are
  asserted in the direct scenarios.

The suite takes about 5 s under `-race`. Run one scenario with
`scripts/dev go test -race -run 'TestScenarios/ARI_renewal' ./test/e2e/`.

### Pebble (`make e2e-pebble`)

`test/pebble.sh start` runs `ghcr.io/letsencrypt/pebble` (with
`PEBBLE_VA_NOSLEEP=1 PEBBLE_WFE_NONCEREJECT=0`) and
`ghcr.io/letsencrypt/pebble-challtestsrv` as `tlsbroker-e2e-pebble` and
`tlsbroker-e2e-challtestsrv` on their own docker network `tlsbroker-e2e`.
Pebble resolves through challtestsrv inside that network, so challtestsrv's
DNS port 8053 is never bound on the host (a development broker's `mockdoh`
usually listens there); only Pebble's defaults are published on 127.0.0.1:
14000 (ACME), 15000 (management) and 8055 (challtestsrv management). If one of
them is taken the target prints `SKIPPED` and succeeds. It writes Pebble's API
TLS root and the root of the certificates it issues to `.claude/tmp/e2e/`;
`test/pebble.sh stop` removes everything. `make e2e-pebble` and `make compat`
share the containers and serialize on `flock .claude/tmp/pebble.lock`.

`test/e2e/pebble_test.go` (build tag `pebble`) boots the broker with
`Providers` unset, so `internal/upstream` talks to Pebble (`UpstreamRootCAs`
= Pebble's minica root), with a fresh random managed zone per run. Route53 is
still `dns01.FakeRoute53`, wrapped by `test/challtest.Route53`, which mirrors
every TXT RRset the broker writes to challtestsrv (`/clear-txt`, `/set-txt`)
before the change call returns; the DNS gate stays on the fake resolver. It
covers new issuance (single and multi-SAN), renewal with `replaces` (sent and
inferred), wildcard (denied without, issued with a wildcard grant) and the
direct API, and checks every chain against Pebble's current intermediate and
root. By hand:

```sh
test/pebble.sh start
scripts/dev env TLS_BROKER_PEBBLE_DIRECTORY=https://127.0.0.1:14000/dir \
  TLS_BROKER_PEBBLE_ROOT=/src/.claude/tmp/e2e/pebble.minica.pem \
  TLS_BROKER_PEBBLE_ISSUER_ROOT=/src/.claude/tmp/e2e/pebble-root.pem \
  TLS_BROKER_PEBBLE_CHALLTESTSRV=http://127.0.0.1:8055 \
  go test -race -tags pebble -run TestPebble -v ./test/e2e/
test/pebble.sh stop
```

The same containers serve the upstream adapter's own Pebble test
(`docs/providers.md`).

### Client compatibility (`make compat`)

`test/compat/run.sh` checks real ACME clients against the shipped image.
It starts Pebble (`test/pebble.sh`), builds the image as
`tls-broker:compat` (never `:local`, which a running test deployment
may use) and runs, on the host network, containers named
`tlsbroker-e2e-compat-*`:

| Service | Address | Role |
|---|---|---|
| broker | 127.0.0.1:18480 | the image, data in `.claude/tmp/compat-data`, one zone `compat.test`, provider `pebble` (configured with `tls-broker config apply`) |
| r53mock | 127.0.0.1:18454 | `test/compat/r53mock`: the Route53 REST API over `dns01.FakeRoute53` (the broker reaches it through `AWS_ENDPOINT_URL_ROUTE_53`), TXT mirrored to challtestsrv, DoH for TXT |
| mockdoh | 127.0.0.1:18453 | the gate's public DNS (`TLS_BROKER_DOH_ENDPOINTS`): test names → 127.0.0.1, CAA closing wildcards, the rest forwarded to r53mock |
| caddy | 127.0.0.1:18443 | `caddy:2-alpine` TLS front (`tls internal`) setting `X-Real-IP` |

Clients: `certbot/certbot:latest`, Ubuntu 20.04's `python3-certbot` (built
from `test/compat/certbot-focal.Dockerfile`), `certbot/certbot:v0.31.0`
(Debian 10's version) with `--webroot -w /tmp`, and `neilpang/acme.sh` both
through the ACME proxy and with the DNS-proxy hook of `docs/dns-proxy.md`
against Pebble directly. Each issues, the chain is compared with Pebble's
intermediate and verified against its root, and each renews; the script also
checks that current certbot fetched `renewalInfo`, that renewals went
upstream with `replaces`, and that the hook left nothing published. It ends
with a PASS/FAIL table and exits non-zero on any FAIL; logs stay in
`.claude/tmp/compat/`. `COMPAT_PLAIN_HTTP=1` points the clients at the broker
over plain http instead of Caddy. The observed versions and behaviours are
in `docs/acme-proxy.md`, "Tested clients". A full run takes a few minutes,
most of it image builds and pulls.

## Running the broker locally

```sh
make build
mkdir -p .claude/tmp/data
TLS_BROKER_DATA_DIR=$PWD/.claude/tmp/data TLS_BROKER_LOCAL_ADMIN_USER=admin \
  TLS_BROKER_LOCAL_ADMIN_PASSWORD=admin bin/tls-broker
```

Then open <http://127.0.0.1:8080/ui/> and log in as `admin`; the session
cookie is not marked Secure for a plain-HTTP login (`sessions.cookie_secure:
auto`). `bin/tls-broker help` lists the maintenance subcommands.

## Mock DNS gate (`mockdoh`, development only)

The DNS gate authorizes a machine when the requested name resolves, in
public DNS, to the machine's address. LAN test names usually do not exist in
public DNS, so for development the broker can ask a mock instead:
`cmd/mockdoh` is a tiny RFC 8484 DoH server (GET and POST wire format)
answering A, CNAME, TXT and CAA from a static table. Names it does not know
are NXDOMAIN, or with `--upstream` forwarded to a real DoH server, which you
want with real Route53 so that DNS-01 propagation checks and CAA lookups
still see public DNS.

```sh
bin/mockdoh --listen 127.0.0.1:8053 \
  --record 'text2.example.com A 192.0.2.10' \
  --record 'www.example.com CNAME text2.example.com' \
  --upstream https://cloudflare-dns.com/dns-query
# or --file records.yaml with
#   records:
#     - text2.example.com A 192.0.2.10
#     - example.com CAA 0 issue "letsencrypt.org"

TLS_BROKER_DOH_ENDPOINTS=http://127.0.0.1:8053/dns-query bin/tls-broker
```

Records use zone-file syntax after `<name> <type>`. The image ships the same
binary as `/usr/local/bin/mockdoh`; in compose run it as a second service
from the same image with `entrypoint: ["/usr/local/bin/mockdoh", ...]`, host
networking and `healthcheck: {disable: true}` (the image's HEALTHCHECK probes
the broker, so it would report the mockdoh container healthy as long as the
broker answers, or unhealthy while it does not). With `TLS_BROKER_DOH_ENDPOINTS` set the broker logs a loud
warning at start-up and every UI page shows "DNS gate is mocked". Never set
it, or run mockdoh, in production: whoever edits the table decides which
machine gets which certificate. `cmd/mockdoh/main_test.go` tests it against
the broker's own `internal/doh` resolver.

## Wiring the broker in tests (`internal/app`)

`app.New(ctx, env, app.Options{...})` builds the complete broker and runs
startup recovery; `Run(ctx)` serves until `ctx` ends and then shuts down in
order. `Options` is the injection point for every external dependency; the
zero value is production:

| Option | Inject | Notes |
|---|---|---|
| `Clock` | `coretest.NewFakeClock(...)` | used by every package and by the housekeeping loop |
| `Providers` | `coretest.NewFakeProviders(coretest.NewFakeCA("primary", clock))` | replaces the upstream registry; the YAML must still list providers with the same names |
| `UpstreamRootCAs` | Pebble's root pool | real adapter against Pebble (when `Providers` is nil) |
| `Route53` | `dns01.NewFakeRoute53(clock)` with `AddZone(id, name)` | replaces the AWS client |
| `Resolver` | `fakeR53.Resolver(coretest.NewFakeResolver())` | public view: the fake resolver plus Route53's published TXT records |
| `Directory` | `coretest.NewFakeDirectory()` | LDAP logins |
| `LDAPTester` | any `core.LDAPTester` | config activation and the UI's *Test LDAP* |
| `Listener` | `net.Listen("tcp", "127.0.0.1:0")` | `App.Addr()` reports it |
| `NewDirectKey` | a pre-generated RSA key | RSA generation is slow under `-race` |
| `HousekeepingInterval` | negative to disable | `App.Housekeep(ctx)` runs one round on demand |
| `Logger` | `slog.New(slog.NewTextHandler(io.Discard, nil))` | |

For the fake CA to validate DNS-01 against what the broker published, call
`ca.SetTXTLookup(fakeR53.LookupTXT)`. After `New`, `App.Config()` (activate
YAML), `App.Store()` (grants, users) and `App.Secrets()` are available;
`App.Handler()` is the full middleware chain for in-process requests (it
answers 503 until `Run` marked the broker ready). An activation before `Run`
is picked up when `Run` starts. `internal/app/app_test.go` boots the whole
broker this way, issues one direct-mode certificate end to end and checks
that shutdown leaves no goroutines behind; `test/e2e/harness_test.go` is the
complete example (restart on the same data directory, TLS front, clients).

## Dependencies

To add a dependency:

```sh
scripts/dev go get example.com/module@latest
scripts/dev go mod tidy
make check
```

and commit `go.mod` and `go.sum` together with the code that uses it.

## Continuous integration

`.github/workflows/ci.yml` runs `make check` exactly as it runs locally, then
builds the image and, on pushes to `main`, publishes it to
`ghcr.io/sshamanov/tls-broker`.

## Commits

One logical change per commit; subject in the imperative, at most 72
characters; body says why and what was validated (see `.gitmessage`). Code,
tests and the documentation they affect go in the same commit.
