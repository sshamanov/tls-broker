# tls-broker

Central TLS broker / ACME proxy for LAN systems: one daemon that fronts upstream
public CAs (Let's Encrypt primary) and Route53 DNS-01, exposing three issuance
modes — clean ACME proxy, DNS proxy, direct certificate API.

`architecture.md` is the source of truth for design. Read it before changing
behaviour; if code and architecture disagree, fix one of them in the same piece
of work rather than leaving them diverged.

Status: pre-implementation. Language/toolchain and the implementation plan are
not settled yet; update this file when they are (build, test, lint commands).

## Working rules

- **Commit everything.** Every change lands in git; no uncommitted work is left
  behind at the end of a task. Small, focused commits.
- **Code, tests and docs are written together but committed separately.** A
  feature is not done until its tests and docs exist, yet a single commit
  contains only one of: code, tests, or docs.
- Scratch files go in `.claude/tmp/` (gitignored), never system temp dirs.
- Project memory lives in `.claude/memory.md` (gitignored).

## Invariants that must never regress

- One downstream ACME order maps to at most one upstream order.
- One direct-mode identifier has at most one concurrent issuance job.
- A valid cached direct cert is served even when upstream is down; an expired
  one is never served.
- Wildcards never succeed without an explicit IP grant with `wildcard=true`.
- Nothing that creates upstream issuance bypasses the admission scheduler.
- ARI renewals stay on the current provider/account while it is healthy.
