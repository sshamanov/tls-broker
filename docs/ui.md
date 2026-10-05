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
| Status | banner only | CA states, queue, rate-limit headroom, certificates in managed zones and their recent issuance (CT), the broker's expiring next and recent issuance | same | plus needs attention (CT problems and refresh errors included), provider details, full budgets, CA accounts, zones and CAA |
| Client access | own, read only | see all with owner; create single-address grants, edit, enable, disable, delete own | plus `wildcard` | plus address ranges, change anyone's |
| Certificates | no | all, with owner; all in managed zones (CT) | same | plus last error and rotate hook |
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
- Certificates in managed zones (right column, first): the Certificate
  Transparency inventory (architecture §31, `internal/ctlog`, through
  `Deps.Inventory`), so every certificate of the zones counts, whoever
  requested it. A sentence on top ("38 current certificates in 4 zones; 2
  need attention. Updated 3h00m ago."), then the first eight identifier sets
  by urgency (expired, then revoked or overdue, then unexpected CA, then
  renewal due, then the rest by renewal point; replaced last). Each row:
  the names, a state badge (*ok*, *renewal due*, *overdue*, *expired*,
  *revoked*, *replaced*, plus *unexpected CA*), a lifetime bar (issue,
  renewal point at two thirds, now, expiry), the CA and "via the broker"
  (serial matches a certificate in the broker's store) or "outside the
  broker"; for an unexpected CA the reason ("Google Trust Services is not
  allowed by the CAA issue records of example.com (allowed:
  letsencrypt.org)"). Link "All in managed zones" to the full list.
  Instead of the list: "switched off" (`ct_inventory.disabled` or no
  inventory wired; admins get the setting's name), "Reading Certificate
  Transparency logs ..." until the first refresh has finished, "not
  available right now" when every zone failed and nothing is known (admins
  also see each zone's error). When some zone failed, a line says the list
  is partly out of date and when it is tried again; only admins see the
  error text.
- Issuance in the last 14 days (right column, second): CT issuances of the
  last 14 days, newest first, at most eight, each a *renewal*, *changed
  names* or *new names*, with CA, source and age, and a count sentence
  ("12 certificates issued: 9 renewals and 3 for new or changed names.").
- Expiring next (broker) and Recent issuance (broker), in a row below:
  the broker's own view, unchanged. Expiring next (broker): the current
  certificate of each identifier set the broker issued, soonest expiry
  first, with its state (*ok*, *due* for renewal, *expired*; renewal is the
  direct cache's schedule, or two thirds of the lifetime for ACME
  certificates, whose clients decide). Recent issuance (broker): the latest
  outcomes from the activity log (certificates issued or failed, orders
  refused, requests denied, DNS proxy publications), in the same words as
  the activity log.

Admins additionally see:
- Needs attention: problems and warnings of the active configuration, no
  zones or providers, LDAP not configured, the most recent LDAP check failed
  (the broker checks at startup and on LDAP setting changes, and counts a
  successful LDAP login or *Test LDAP* as a check; see
  `docs/authentication.md`), zones without a hosted zone (no `hosted_zone_id` and discovery
  by name failed), zones whose CAA does not protect wildcards, zones whose CAA
  does not authorize a configured provider, providers whose account URL cannot
  be read, open provider circuits, CT zones that could not be refreshed
  (with the last success and the error), CT certificates expired, overdue
  or revoked without a successor, and CT certificates from a CA the zone's
  CAA does not allow (at most five named per line).
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

**Client access** (`/ui/grants`). Addresses allowed to request certificates
(IP grants). The page says "address" for a grant and "address range" for one
wider than /32, never "network"; "grant" stays the code and audit term. One
page for everyone: every grant with its owner (column "Address"), filtered by
owner (everyone, mine, or one user). The only place to add is the "Add
address" panel below the table (no header button); the grant is owned by you.
Users who are not admins enter a single IPv4 address (stored as /32; field
"IPv4 address", placeholder "10.1.2.3, 10.1.2.4 or 10.1.2.3/32", no mention of
ranges);
a range answers 403 with "Only administrators can add an address range. Add
a single address (10.1.2.3 or 10.1.2.3/32)." Admins may also enter an IPv4
CIDR from /8 to /32 (stored masked; field "IPv4 address or range",
placeholder "10.1.2.3, 10.1.2.4 or 10.1.2.0/24", hint that ranges such as
/24 or /16 are allowed). A prefix wider than /8 answers 400 "A range wider than /8 is
refused." for everyone; IPv6 is refused too. Flashes and the activity log
read "Added address 10.1.2.3/32.", "Disabled address …" and so on.
The field takes several entries separated by commas and/or whitespace, at
most 50 per submit (more answers 400). Every entry is checked with the rules
above before anything is stored: if any is refused, nothing is added and the
form keeps the text and lists each refused entry with its reason ("Nothing
was added: 2 of 4 entries were refused."; 400 if any entry is malformed or
too wide, else 403). Duplicates in the input collapse after masking
(`10.1.2.3` and `10.1.2.3/32` are one). An entry the user already owns with
the same prefix is skipped, not an error, and adding it again never changes
it: the flash names it and points to Edit ("10.1.2.4/32 is already listed as
yours; use Edit on its row to change it."), as a warning when nothing was
added. Another user's grant for the same prefix does not count: the entry is
added as a separate grant owned by you (grants are per owner; either can be
deleted without affecting the other). The note and the wildcard choice apply to every new grant, and each
is audited as its own `grant_change`. The flash lists what was added
("Added 3 addresses: …", the first ten named). The wildcard checkbox and the "Wildcards"
column appear only for `wildcard_allowed` and `admin`; for other users the
page does not mention wildcards at all. The server enforces the role too. Enable, disable and
delete appear on your own grants, and on all grants for an admin; posting an
action on someone else's grant answers 403. A non-admin's own disabled grant
wider than /32 (from before ranges became admin-only) offers delete but not
enable, and enabling it answers 403; such grants stay in force while enabled,
and admins review them here. Edit (`GET`/`POST /ui/grants/{id}/edit`, a separate
page, no script needed) changes the note and, for `wildcard_allowed` and
`admin`, the wildcard switch; the address, owner and enabled state stay (the
page says to delete and add to use another address). It appears on your own
single addresses, and on every grant for an admin, who keeps the owner when
editing someone else's. Someone else's grant answers 403, and so does a
non-admin's own grant wider than /32 ("Only administrators can edit an
address range."). Without the wildcard role the form has only the note and
keeps the switch as it is; posting `wildcard=true` answers 403 and changes
nothing. A saved edit flashes "Saved address 10.1.2.3/32." and is audited
as one `grant_change` ("updated grant 10.1.2.3/32: wildcard false→true, note
changed"; the activity log reads "Changed address 10.1.2.3/32."); an edit
that changes nothing is not audited. A blocked user sees only their own
grants, read-only. Changes are audited as `grant_change`.

**Certificates** (`/ui/certificates`). Every user who is not blocked sees all
certificates. ACME-mode certificates (identifiers, owner, provider, serial,
validity, issue time, observed client check interval of the lineage, replaced
or current) and the direct cache (identifier, owner, provider, generation,
expiry, renew-at, last fetch time and address, last attempt). The owner is
the owner of the grant that authorized the order that produced the
certificate (for a direct entry: its active generation's certificate),
resolved live: the username and the grant's address; "deleted grant" with
the requesting address when the grant is gone; "no owner, DNS match from"
the requesting address when the names resolved to the requester; "unknown"
for certificates issued before owners were recorded (see
`docs/data-model.md`). A failing direct entry shows its last error text to
admins only; others see "renewal failing" and the failure count. Filters:
name substring, provider, kind, include expired; ACME results are paged.
Hook: when `Deps.Rotator` (`ui.KeyRotator`) is set, admins get a "Rotate key"
button per direct entry (`POST /ui/certificates/rotate`); without it the
button is absent and the route is 404.

Two tabs on top: "Issued by the broker" (the lists above) and "All in
managed zones" (`/ui/certificates/zones`): one row per identifier set of
the CT inventory with its newest certificate: names, state badge (and the
CAA reason for an unexpected CA), lifetime bar, CA and serial, "via the
broker" or "outside the broker", and the earlier certificates of the set in
a disclosure (dates, CA, revoked). A sentence on top counts sets, zones and
certificates and says when the data was updated and the next refresh.
Filters: name substring, zone (any managed zone), state (needs attention,
renewal due, ok, expired, replaced) and who obtained it (via the broker,
outside). A note under the table explains the states and that CT does not
show which ACME account was used. Same access as the certificates page.

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

**Documentation** (`/ui/docs`). A reader for the user guide,
`docs/guide.md` in the repository, shipped in the image as
`/usr/share/tls-broker/docs/guide.md` (there is no setting to move it).
Every logged-in user may read it, blocked users included: it is reading only
and explains how access works. The guide is one document: its contents (the
level-2 and level-3 headings, which the document's own "Contents" list
mirrors) form the column on the left, sticky on wide screens and scrolling
by itself, with the section being read marked (`ui.js`); the text is one
continuous column of at most 75 characters. On narrow screens the contents
become a block of section links (level 2 only) above the text. The
document's "Contents" list itself is not repeated in the text. Links to a
section are ordinary `#anchors` (`/ui/docs#getting-access`). The addresses
of the pages the guide used to be split into, `/ui/docs/<page>`
(`getting-started`, `web-ui`, `acme-proxy`, `dns-proxy`, `direct`,
`troubleshooting`, `api`), answer `301` to `/ui/docs#<section>`
(`guide.MovedPages`), so old links and bookmarks keep working; any other
name is the 404 page. The engineering and operator references in `docs/` are
not served. The guide is rendered by `internal/guide` with goldmark (GFM,
GitHub-compatible heading IDs, raw HTML never passed through) on first
request and cached by modification time and size. While rendering:
`https://broker.example.com` becomes the active configuration's
`server.external_url`; links to other repository files show their text
followed by "(in the repository: docs/...)" instead of a broken link; images
show their alternative text. Code blocks scroll inside themselves and get a
Copy button (clipboard API, or a selected textarea on plain-HTTP pages).
Without the guide the page says so (logged once). The Status page ("How to
get a certificate") and Client access ("How access works") link to its
`#getting-access` section.

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
- The lifetime bar (status page, certificates pages) shows a certificate's
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
