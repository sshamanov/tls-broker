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
- `internal/deps` — temporary blank imports that keep `go.mod` complete (see
  below).
- `deploy/` — Dockerfile, compose file, `.env.example`.

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

## Dependencies

`go.mod` and `go.sum` are written by the skeleton step and pin everything the
project needs. `internal/deps/deps.go` blank-imports each dependency so
`go mod tidy` keeps them until real code imports them; the app-wiring step
removes that file.

While packages are being built in parallel, do not edit `go.mod`. If a
dependency is missing, report it. Outside that phase, to add one:

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
