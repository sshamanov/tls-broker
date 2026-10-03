# Development

Go is not needed on the host. Every build and test runs in the `golang`
container through `scripts/dev`; `make` targets wrap the common cases.

## Commands

| Command | What it does |
|---|---|
| `make check` | gofmt check, `go vet ./...`, `go test -race ./...`. Must be green before every commit. |
| `make test` | `go test ./...` without the race detector (faster). |
| `make fmt` | `gofmt -w` on the source tree. |
| `make build` | Static binary in `bin/tls-broker`. |
| `make image` | Container image from `deploy/Dockerfile`. |
| `make e2e` | In-process end-to-end tests (`test/e2e`). Placeholder until wave 4. |
| `make e2e-pebble` | Upstream adapter against Pebble. Placeholder until wave 4. |
| `make compat` | Real certbot / acme.sh against the broker. Placeholder until wave 4. |
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
2. **In-process end-to-end** (`test/e2e`, `make e2e`): the whole broker wired
   with the fake CA, fake Route53, fake resolver, fake LDAP and fake clock.
3. **Pebble** (`make e2e-pebble`): the real upstream adapter against Pebble and
   challtestsrv containers.
4. **Compatibility** (`make compat`): real certbot and acme.sh containers.
5. **Let's Encrypt staging and a production canary** are run by the operator
   with real credentials; they are not automated here.

Layers 3 and 4 run in CI only on manual dispatch (`.github/workflows/e2e.yml`).

Rules that keep tests trustworthy:

- Every external dependency is reached through an interface in `core` and has a
  fake. A new external call brings its fake in the same change.
- Do not skip a failing test or weaken an assertion to get green.
- Scratch files go in `.claude/tmp/` or `t.TempDir()`, never the system temp
  directory.

## Running the broker locally

```sh
make build
mkdir -p .claude/tmp/data
TLS_BROKER_DATA_DIR=$PWD/.claude/tmp/data TLS_BROKER_LOCAL_ADMIN_USER=admin \
  TLS_BROKER_LOCAL_ADMIN_PASSWORD=admin bin/tls-broker
```

Then open <http://127.0.0.1:8080/ui/> and log in as `admin`. On plain HTTP
set `sessions.cookie_secure: false` in the configuration first (for example
with `bin/tls-broker config apply <file>` before the start), or the browser
drops the session cookie. `bin/tls-broker help` lists the maintenance
subcommands.

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
that shutdown leaves no goroutines behind.

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
