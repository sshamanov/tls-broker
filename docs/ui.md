# Web UI

The UI is the primary operator surface. It is server-rendered `html/template`
with embedded assets (`internal/ui`): one small stylesheet, an SVG favicon and
a few lines of JavaScript (`ui.js`) that ask for confirmation before destructive
forms. There is no build step. Everything lives under `/ui/`.

Code: `internal/ui`. The handler (`ui.New(ui.Deps{...})`, mount it at `/ui/`)
depends on the `core` ports plus `*auth.Service` for sessions and cookies. Per
request the chain is: security headers, `auth.Middleware`, `auth.CSRF`, then
the route's role check.

## Security properties

- Templates are auto-escaped; user text (grant notes, usernames, audit
  details) is never trusted.
- Every authenticated page sends `Cache-Control: no-store`. Static assets
  (`/ui/static/...`, URLs carry a content hash) are cached for a year.
- Headers: a CSP without inline script or style (`default-src 'none'`,
  `script-src 'self'`, `style-src 'self'`, `form-action 'self'`,
  `frame-ancestors 'none'`), `X-Frame-Options: DENY`,
  `X-Content-Type-Options: nosniff`, `Referrer-Policy: same-origin`.
- Every POST needs the session's CSRF token (hidden field `csrf_token`); the
  login form is protected by the `SameSite=Strict` cookie and a refusal of
  `Sec-Fetch-Site: cross-site`.
- Methods are part of the route: a wrong method is 405. Anonymous GETs redirect
  to `/ui/login?next=...` (only local `/ui/` targets are honoured); anonymous
  POSTs get 401; a missing role gets a 403 page. Any other `GET` under `/ui/`
  renders the styled 404 page (with the navigation when a session exists; no
  login is required to see it).
- Form bodies are bounded in the handler, independently of the CSRF
  middleware's 1 MiB cap (which only applies when the token is in the form
  field): 64 KiB for ordinary forms, the YAML editor and the secret value
  allow their own maximum plus 64 KiB. A larger body is answered 413.
- Flash messages travel in a short-lived `SameSite=Strict` cookie and are
  rendered escaped.
- Secret values are write-only: no page, flash or audit event ever contains
  one.
- Errors that are not the user's fault show a generic page with the request id;
  the cause is only in the server log.

## Roles

| | blocked | normal | wildcard_allowed | admin |
|---|---|---|---|---|
| Log in, see banner | yes | yes | yes | yes |
| Dashboard | banner only | counts, providers, budgets, recent issuance activity | same | plus accounts, zones, warnings, all recent events |
| My grants | read only | create, enable, disable, delete own | plus `wildcard` | same |
| Certificates | no | yes | yes | yes (plus rotate hook) |
| Activity log | issuance activity | issuance activity | issuance activity | all events, with detail |
| Admin pages | no | no | no | yes |

Role and block changes apply to open sessions at once (auth reads the user on
every request). A blocked user has no rights at all; their existing grants stay
in force (grants are independent of their owner).

## Pages

**Login** (`/ui/login`). Local admin (break-glass) or LDAP, through
`core.Authenticator`. Wrong credentials: 401 "Invalid username or password".
LDAP down or unconfigured (and not the local admin): 503 with a clear message.
Five failures per minute lock the pair out (429). A login from a browser
that still holds a session replaces it: the old session row is deleted.
Logout is a POST.

**Banners.** `Deps.Banners` are process-level warnings the app passes in,
such as a development build whose DNS gate is mocked. They are shown at the
top of every page, the login page included, to every user.

**Dashboard** (`/ui/`).
- Warnings (admin): problems and warnings of the active configuration, no
  zones or providers, LDAP not configured, LDAP not tested since start or last
  test failed, zones without a hosted zone (no `hosted_zone_id` and discovery
  by name failed), zones whose CAA does not protect wildcards, zones whose CAA
  does not authorize a configured provider, providers whose account URL cannot
  be read, open provider circuits.
- Counts: valid ACME certificates, orders in flight, direct entries.
- Providers: health, circuit state, retry-after, slots, last error; budget
  usage per bucket (`Scheduler.Snapshot()`). A budget's meter turns yellow at
  50 % and red at 80 %; a bucket with `Used >= Limit` carries an "exhausted"
  badge.
- Admin: the broker's account URL at each enabled provider (copy it into the
  CAA `accounturi` parameter), and per managed zone the hosted zone in effect
  (the configured ID, or the one the DNS-01 engine discovered by name, or why
  discovery failed; see `docs/dns01.md`) and the CAA verdict from
  `CAAChecker` with ready-to-paste CAA records. CAA and account lookups run in
  parallel with an 8 s limit, so a slow resolver delays the page, never breaks
  it.
- Recent activity (the activity log's first ten events for the viewer).

**My grants** (`/ui/grants`). Lists your grants; create one from an IPv4
address (stored as /32) or IPv4 CIDR (stored masked) with a note. `/0` and IPv6
are refused. The wildcard checkbox appears only for `wildcard_allowed` and
`admin`; the server enforces it too. Enable, disable and delete act on your own
grants only (someone else's grant answers 404).

**Certificates** (`/ui/certificates`). ACME-mode certificates (identifiers,
provider, serial, validity, issue time, observed client check interval of the
lineage, replaced or current) and the direct cache (identifier, provider,
generation, expiry, renew-at, last fetch time and address, last attempt and
error). Filters: name substring, provider, kind, include expired; ACME results
are paged. Hook: when `Deps.Rotator` (`ui.KeyRotator`) is set, admins get a
"Rotate key" button per direct entry (`POST /ui/certificates/rotate`); without
it the button is absent and the route is 404. `internal/direct` is expected to
provide the implementation when the app is wired.

**Activity log** (`/ui/audit`). Filters: type, mode, contains (IP, name, user,
reason; admins also detail), from and to date. Paging by time ("Older"
continues before the last event shown; events with exactly the same timestamp
at a page boundary may be skipped). Users who are not admins see the issuance
activity: `gate`, `order`, `issue`, `dns_present` and `grant_change` events,
successes, denials and failures alike, each with its outcome and a sentence
built from type, result and reason (never the free-text detail, which can hold
resolver or upstream error text; their search does not match it either).
Admins see every event type with the detail column. See
`docs/observability.md`.

**Admin, Users** (`/ui/admin/users`). List with source (LDAP or local), role,
state and last login. Set role, block, unblock. The local break-glass admin and
your own account cannot be changed here. Each change is audited as
`user_change`.

**Admin, Grants** (`/ui/admin/grants`). All grants with their owner; enable,
disable, delete. Audited as `grant_change`.

**Admin, Config** (`/ui/admin/config`). The active generation's YAML in an
editor (open an older one with "View"). *Validate* shows problems with their
field paths (`zones[0].hosted_zone_id: ...`), warnings, and the LDAP test when
LDAP settings changed. *Activate* validates again and stores a new generation;
on failure nothing is stored and the same problems are shown (HTTP 422).
*Test LDAP* tests the active generation's LDAP (connect, service bind, filter);
the result feeds the dashboard warning. The generation list offers *Rollback*,
which makes an old generation's content current again (as a new generation).
All changes are audited as `config_change`.

**Admin, Secrets** (`/ui/admin/secrets`). Secrets referenced by the active
configuration with set/missing state; the stored names; set or replace a secret
(name `[a-z0-9][a-z0-9._-]*`, value write-only, trailing newlines trimmed);
delete (with a warning when the active configuration still refers to it).
Names the broker writes itself (`provider-account-key.*`,
`provider-account-url.*`) are shown but cannot be set or deleted here.

**Admin, Providers** (`/ui/admin/providers`). Per provider: health, retry-after,
consecutive failures, last error, slots, reservations, directory URL, account
URL, capabilities and budget usage (same meters and "exhausted" marker as the
dashboard). There is no circuit reset: `core` exposes none, and circuits close
by themselves.

## Presentation

Tables fill their box and scroll horizontally when they are wider than the
viewport; a shaded edge shows which side has more. Timestamps are `<time>`
elements (UTC, never wrapped). Persistent notices (process banners, the
blocked-account notice) are `role="status"` regions; only the outcome of an
action is an alert. The YAML editor does not soft-wrap lines.

## First start

1. Start the container with `TLS_BROKER_LOCAL_ADMIN_USER` and
   `TLS_BROKER_LOCAL_ADMIN_PASSWORD` (and optionally `TLS_BROKER_ADMINS`). Log
   in at `/ui/login` as the local admin.
2. **Secrets**: set the Route53 access key and secret key, and EAB keys for any
   provider that needs them, under the names you will reference.
3. **Config**: edit the YAML: `server.external_url`, `zones` (name, and the
   hosted zone id unless it is to be discovered by name), `providers` (directory URL, `caa_issuers`, `account_uri_honoured`),
   `route53` secret names. *Validate*; fix the listed problems (a missing
   secret is reported by name).
4. *Activate*. The dashboard now lists providers, and the broker's account URL
   at each provider appears (registered on first use).
5. **CAA records**: copy the account URLs from the dashboard into the zones'
   CAA records (`issue`/`issuewild` with `accounturi`; the dashboard prints
   suggested records). Reload the dashboard until each zone reads "wildcard
   protected" and no provider is missing.
6. **LDAP**: add the `ldap:` section (bind password as a secret). *Validate*
   tests it; *Activate*; then *Test LDAP* clears the dashboard warning.
7. Log in as an LDAP user once, then promote LDAP admins under Admin, Users (or
   list them in `TLS_BROKER_ADMINS`). Keep the local admin for emergencies.
