# Web UI

The UI is the primary operator surface. It is server-rendered `html/template`
with embedded assets (`internal/ui/static`): one stylesheet, self-hosted IBM
Plex fonts, an SVG favicon and two small scripts: `theme.js` applies the saved
colour theme before the page paints, `ui.js` asks for confirmation before
destructive forms, drives the theme switch and the narrow-screen menu, and
adds copy buttons to the documentation's code blocks.
Every page works without JavaScript. There is no build step. Everything lives
under `/ui/`.

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
  `script-src 'self'`, `style-src 'self'`, `font-src 'self'`, `form-action 'self'`,
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
| Status | banner only | CA states, queue, rate-limit headroom, recent issuance, expiring next | same | plus needs attention, provider details, full budgets, CA accounts, zones and CAA |
| Client access | own, read only | see all with owner; create single-address grants, enable, disable, delete own | plus `wildcard` | plus network ranges, change anyone's |
| Certificates | no | all, with owner | same | plus last error and rotate hook |
| Activity log | issuance activity | issuance activity | issuance activity | all events, with detail |
| Documentation | yes | yes | yes | yes |
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

**Status** (`/ui/`). Everyone who is not blocked sees a short status:
- Certificate authorities: one state per enabled CA: *operational*,
  *degraded* (admitting, but its last answers were errors or rate limits) or
  *unavailable* (circuit open; with the retry time).
- Queue: orders in flight, requests waiting for an admission slot, slots in
  use (`Scheduler.Snapshot()`, `OrderStore.ListActive`).
- Rate-limit headroom: per CA the new-order budget and the most used
  per-domain and per-set budget, as gauges with a level: *ok*, *caution*
  from 75 % used, *exhausted* when nothing is left.
- Recent issuance: the latest outcomes from the activity log (certificates
  issued or failed, orders refused, requests denied, DNS proxy
  publications), in the same words as the activity log.
- Expiring next: the current certificate of each identifier set, soonest
  expiry first, with its state (*ok*, *due* for renewal, *expired*; renewal
  is the direct cache's schedule, or two thirds of the lifetime for ACME
  certificates, whose clients decide).

Admins additionally see:
- Needs attention: problems and warnings of the active configuration, no
  zones or providers, LDAP not configured, the most recent LDAP check failed
  (the broker checks at startup and on LDAP setting changes, and counts a
  successful LDAP login or *Test LDAP* as a check; see
  `docs/authentication.md`), zones without a hosted zone (no `hosted_zone_id` and discovery
  by name failed), zones whose CAA does not protect wildcards, zones whose CAA
  does not authorize a configured provider, providers whose account URL cannot
  be read, open provider circuits.
- Provider details (health, circuit, retry-after, slots, waiting, last error)
  and every budget bucket with its meter (yellow at 50 %, red at 80 %; a
  bucket with `Used >= Limit` carries an "exhausted" badge), plus counts of
  valid ACME certificates and direct entries.
- CA accounts for CAA: the broker's account URL at each enabled provider (copy
  it into the CAA `accounturi` parameter).
- DNS zones and CAA: per managed zone the hosted zone in effect (the
  configured ID, or the one the DNS-01 engine discovered by name, or why
  discovery failed; see `docs/dns01.md`) and the CAA verdict from
  `CAAChecker` (for a protected zone that pins accounts: "broker's account
  pinned", "not pinned" or "unknown", with a warning when it is not pinned,
  because the broker then cannot issue the zone's wildcards itself) and
  ready-to-paste CAA records following the architecture §9 policy: an
  unpinned `issue` per CA, one `issuewild` pinned with `accounturi` to the
  broker's account at the most preferred provider that honours `accounturi`
  (Let's Encrypt; never one per provider), and a reminder to add one pinned
  `issuewild` line per ACME account of your own that needs wildcards. CAA and account lookups run in
  parallel with an 8 s limit, so a slow resolver delays the page, never breaks
  it.

**Client access** (`/ui/grants`). Networks allowed to request certificates (IP grants). One page for everyone: every grant with its owner,
filtered by owner (everyone, mine, or one user). Create one with a note; it is
owned by you. Users who are not admins enter a single IPv4 address (stored as
/32; the field reads "IPv4 address"); a network range answers 403 with
"Only administrators can add a network range." Admins may also enter an IPv4
CIDR (stored masked; the field reads "IPv4 address or network"). `/0` and IPv6
are refused for everyone. The wildcard checkbox appears only for
`wildcard_allowed` and `admin`; the server enforces it too. Enable, disable and
delete appear on your own grants, and on all grants for an admin; posting an
action on someone else's grant answers 403. A non-admin's own disabled grant
wider than /32 (from before ranges became admin-only) offers delete but not
enable, and enabling it answers 403; such grants stay in force while enabled,
and admins review them here. A blocked user sees only their own
grants, read-only. Changes are audited as `grant_change`.

**Certificates** (`/ui/certificates`). Every user who is not blocked sees all
certificates. ACME-mode certificates (identifiers, owner, provider, serial,
validity, issue time, observed client check interval of the lineage, replaced
or current) and the direct cache (identifier, owner, provider, generation,
expiry, renew-at, last fetch time and address, last attempt). The owner is
the owner of the grant that authorized the order that produced the
certificate (for a direct entry: its active generation's certificate),
resolved live: the username and the grant's network; "deleted grant" with
the requesting address when the grant is gone; "no owner, DNS match from"
the requesting address when the names resolved to the requester; "unknown"
for certificates issued before owners were recorded (see
`docs/data-model.md`). A failing direct entry shows its last error text to
admins only; others see "renewal failing" and the failure count. Filters:
name substring, provider, kind, include expired; ACME results are paged.
Hook: when `Deps.Rotator` (`ui.KeyRotator`) is set, admins get a "Rotate key"
button per direct entry (`POST /ui/certificates/rotate`); without it the
button is absent and the route is 404.

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

**Documentation** (`/ui/docs`, `/ui/docs/{page}`). A reader for the user
guide, `docs/guide` in the repository, shipped in the image at
`/usr/share/tls-broker/docs` (there is no setting to move it). Every
logged-in user may read it, blocked users included: it is reading only and
explains how access works. Only the usage pages are served: the index
(`docs/guide/README.md`, at `/ui/docs`) and the pages it lists, by file name
without `.md`; any other name, `README`, a path with `..` or more segments
is the 404 page, and there is no directory listing. The engineering and
operator references in `docs/` are not served. The guide's navigation, in
the index's order and groups, is on the left (a block of links above the
page on narrow screens), the page in a readable column of at most 75
characters, and "On this page" (its h2 and h3 headings) on the right on
wide screens. Pages are rendered by `internal/guide` with goldmark (GFM,
GitHub-compatible heading IDs, raw HTML never passed through) on first
request and cached per file by modification time and size. While
rendering: `https://broker.example.com` becomes the active configuration's
`server.external_url`; links to listed guide pages go to `/ui/docs/<name>`
(anchors kept); links to other repository files show their text followed by
"(in the repository: docs/...)" instead of a broken link; images show
their alternative text. Code blocks scroll inside themselves and get a
Copy button (clipboard API, or a selected textarea on plain-HTTP pages).
Without the documentation directory the page says so (logged once). The
Status page ("How to get a certificate") and Client access ("How access
works") link into the guide.

**Users and roles** (`/ui/admin/users`, admin). List with source (LDAP or local), role,
state and last login. Set role, block, unblock. The local break-glass admin and
your own account cannot be changed here. Each change is audited as
`user_change`.

**Configuration** (`/ui/admin/config`, admin). The active generation's YAML in an
editor (open an older one with "View"). *Validate* shows problems with their
field paths (`zones[0].hosted_zone_id: ...`), warnings, and the LDAP test when
LDAP settings changed. *Activate* validates again and stores a new generation;
on failure nothing is stored and the same problems are shown (HTTP 422).
*Test LDAP* tests the active generation's LDAP (connect, service bind, filter)
on demand; like the broker's own checks, its result feeds the status page
warning. The generation list offers *Roll back*,
which makes an old generation's content current again (as a new generation).
All changes are audited as `config_change`.

**Secrets** (`/ui/admin/secrets`, admin). Secrets referenced by the active
configuration with set/missing state; the stored names; set or replace a secret
(name `[a-z0-9][a-z0-9._-]*`, value write-only, trailing newlines trimmed);
delete (with a warning when the active configuration still refers to it).
Names the broker writes itself (`provider-account-key.*`,
`provider-account-url.*`) are shown but cannot be set or deleted here.

**Certificate authorities** (`/ui/admin/providers`, admin; nav "CAs"). Per provider: health, retry-after,
consecutive failures, last error, slots, reservations, directory URL, account
URL, capabilities and every budget as a gauge (same levels as the status page). There is no circuit reset: `core` exposes none, and circuits close
by themselves.

## Presentation

The look is an engraved certificate: ink on paper, hairline rules (a double
frame only around the sign-in panel),
one intaglio blue for links and the current page. Colour marks state only,
and every state also has a word: green *ok*, brass *caution* or *due*, seal red
*failed*, *exhausted* or *expired*.

- Tokens are CSS custom properties on `:root` (ink, paper, sheet, intaglio,
  brass, seal red, ok green, rules), with a dark set under
  `prefers-color-scheme: dark` and again under `[data-theme="dark"]`. Text
  colours meet WCAG AA on both backgrounds; brass has a darker text variant
  for that reason.
- Theme: *Auto* (follows the system), *Light* or *Dark* in the sidebar,
  remembered in the browser's `localStorage` (when storage is blocked the
  choice still applies to the page). `theme.js` is loaded without `defer`
  before the stylesheet so the page never flashes the wrong theme; the CSP
  allows no inline script.
- Type: IBM Plex Sans for text, IBM Plex Mono only for identifiers (names,
  addresses and networks, serials, URLs, YAML). Latin-1 subsets of Sans 400,
  500, 600 and Mono 400 are served from `/ui/static/fonts/` under the SIL Open
  Font License (`OFL.txt` next to them).
- Layout: a left sidebar (brand, Status, Certificates, Client access,
  Activity, Documentation, an Administration group for admins, then the user, the theme
  switch and Log out). Below 48rem it folds into a top bar with a Menu button.
  Every page has a title, a one-line description and, where there is one,
  its primary action. The status page is a two-column grid on wide screens.
- The lifetime bar (status page, certificates page) shows a certificate's
  validity from issue to expiry with the renewal point as a tick and now as a
  marker; the elapsed part is blue, brass once renewal is due, red when
  expired. Rate-limit gauges use the same drawing. Both are SVG whose
  geometry comes from attributes computed on the server: the CSP allows no
  `style` attributes.
- Tables fill their box and scroll horizontally when they are wider than the
  viewport; a shaded edge shows which side has more; identifiers and times do
  not wrap. Nothing scrolls the page sideways at 360px. Timestamps are
  `<time>` elements (UTC). Keyboard focus is always visible; motion is off
  under `prefers-reduced-motion`.
- Persistent notices (process banners, the blocked-account notice) are
  `role="status"` regions; only the outcome of an action is an alert. Empty
  states say what to do next. Blocked users and 403, 404 and 500 answers get
  pages in the same layout; the login page is a centred sign-in panel. The
  YAML editor does not soft-wrap lines.

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
4. *Activate*. The status page now lists providers, and the broker's account URL
   at each provider appears (registered on first use).
5. **CAA records**: copy the account URLs from the status page into the zones'
   CAA records (`issuewild` with `accounturi`; the status page prints
   suggested records). Your own ACME clients that need wildcards get pinned
   `issuewild` records of their own. Reload the status page until each zone
   reads "wildcard protected" and no provider is missing.
6. **LDAP**: add the `ldap:` section (bind password as a secret). *Validate*
   tests it; *Activate*. The broker then checks LDAP once in the background;
   a failure appears under *Needs attention*.
7. Log in as an LDAP user once, then promote LDAP admins under Users and roles (or
   list them in `TLS_BROKER_ADMINS`). Keep the local admin for emergencies.
