# AGENTS.md

Guidance for AI agents working in this repository. Keep this file short; it is a map, not a manual.
`CLAUDE.md` is a symlink to this file so any agent looking for either name finds the same rules.

## What this is

A central TLS broker / ACME proxy for LAN systems: one Go daemon that fronts
public CAs (Let's Encrypt primary, alternates as fallback) and Route53 DNS-01,
exposing three issuance modes — clean ACME proxy, DNS proxy, direct certificate
API — plus an LDAP-backed web UI. Upstream CA rate limits are the scarce
resource; protecting them is a design requirement.

## Source-of-truth map

| Concern | Authority |
|---|---|
| System shape, trust model, invariants | `architecture.md` |
| Package layout, contracts between packages, build order | `docs/plan.md` |
| User-facing usage guide, shown in the app's Documentation reader and copied to Confluence by `tls-broker docs publish` | `docs/guide/` (index `docs/guide/README.md`) |
| Operator and API reference documentation | `docs/*.md` (index `docs/README.md`) |
| How to build, run and test | `docs/development.md`, `Makefile` |

## Rules for agents

1. Read this file, `architecture.md` and `docs/plan.md` before changing anything.
2. Code, tests and docs agree at every commit. A change that alters behaviour
   updates its tests and the relevant doc in the same commit. Never leave stale
   code, tests or docs behind.
3. Commit everything, as soon as a logical step is complete and green. One
   logical change per commit; subject = intent (imperative, max 72 chars),
   body = why and what was validated. No file lists, no trailers.
4. Never add AI/model attribution (`Co-Authored-By`, session links or similar)
   to commits or pull requests.
5. All builds and tests run in docker through `make` / `scripts/dev`. Go is
   not installed on the host. Development uses plain `docker run --network
   host` with the repo mounted; compose is for shipping.
6. Every external dependency (upstream CA, Route53, DoH, LDAP, clock) is used
   through a Go interface and has a fake. New external calls need a fake in the
   same change.
7. Do not skip a failing test or weaken an assertion to get green.
8. Never commit secrets, `.env`, data directories or SQLite files.
9. Scratch files go in `.claude/tmp/` (gitignored), never system temp dirs.
   Go tests use `t.TempDir()`.
10. Do not add abstractions, services or infrastructure that `architecture.md`
    does not call for. Simpler wins.

## Invariants that must never regress

- One downstream ACME order maps to at most one upstream order.
- One direct-mode identifier has at most one concurrent issuance job.
- A valid cached direct cert is served even when upstream is down; an expired
  one is never served.
- Wildcards never succeed without an explicit IP grant with `wildcard=true`.
- Nothing that creates upstream issuance bypasses the admission scheduler.
- ARI renewals stay on the current provider/account while it is healthy.

## Commands

`make check` (gofmt, vet, race tests), `make test`, `make build`, `make image`,
`make e2e`. `scripts/dev <cmd...>` runs any command in the Go dev container.
