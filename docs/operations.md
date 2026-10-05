# Operations

Day-to-day care of a running broker: backup and restore, what happens at a
restart, and runbooks for the situations that need an operator. Paths are
inside the container (`/data` = `deploy/data` on the host). Commands run with
`docker compose exec tls-broker tls-broker <command>`; `tls-broker help`
lists them.

## Backup

What to back up (architecture §23), in order of importance:

| What | Where | How |
|---|---|---|
| SQLite (users, grants, accounts, orders, certificates, budgets, provider state, direct-cache metadata) | `/data/state.db` | **never copy the live file**; take a snapshot with `tls-broker backup` |
| Configuration generations | `/data/config/` | plain copy (files are immutable; `current` is a symlink) |
| Secrets: upstream CA account keys and URLs, EAB keys, Route53 keys, LDAP bind password | `/data/secrets/` | plain copy; **treat the backup as secret** |
| Direct-mode certificate cache (keys and chains) | `/data/certs/` | plain copy; contains private keys |
| Audit history (optional, can be backed up separately) | `/data/audit/` | plain copy |

The CA account keys (`provider-account-key.*`) matter most after the
database: losing them means a new account at the CA, which breaks ARI
continuity and the `accounturi` in your CAA records.

A consistent backup while the broker runs:

```sh
# 1. database snapshot (VACUUM INTO; does not block the broker)
docker compose exec tls-broker tls-broker backup /data/backup-state.db
# 2. everything else, plus the snapshot, from the host
cd deploy
tar czf /backup/tls-broker-$(date +%F).tgz \
    data/backup-state.db data/config data/secrets data/certs data/audit
rm data/backup-state.db
```

`backup` refuses to overwrite an existing file. The snapshot is a complete
database without WAL files and opens as it is. Copy the directories after the
snapshot: a direct-cache generation newer than the snapshot is fine (startup
verification prefers a complete newer generation), an older one is repaired
too.

## Restore

Stop the broker, then restore in this order (architecture §23):

1. `config/` (all generation files and the `current` link);
2. `secrets/` (CA account keys first; mode 0700 directory, 0600 files);
3. the database: the snapshot copied to `state.db`, with any old
   `state.db-wal` and `state.db-shm` removed;
4. `certs/`;
5. `audit/` if wanted;
6. `chown -R 1000:1000 data` (your `PUID:PGID`) and start the broker.

Startup reconciliation then repairs whatever the backup caught in flight (see
below). Orders that were in progress at backup time fail or resume; ACME
clients simply retry.

## What a restart does

Startup is ordered (architecture §20, `internal/app`); the broker reports
ready on `/healthz` only after all of it:

- **Configuration:** a missing or broken `current` link is pointed at the
  newest generation that validates (logged as a warning); no usable
  generation stops the broker.
- **Provider state:** circuits and Retry-After dates are restored, so a
  restart never hammers a CA that asked to back off. Budget reservations are
  restored.
- **DNS-01:** every non-terminal challenge row is reconciled with Route53:
  records still wanted are re-published, records of finished challenges
  removed. A failure is logged and retried at the next start.
- **ACME orders:** an order whose upstream call may have happened without
  its URL being recorded is marked invalid (its new-order budget counted as
  spent, never a second upstream order); orders with an upstream URL resume
  preparation or finalization; ready orders wait for the client's CSR.
  Reservations that belong to no live order are settled.
- **Direct cache:** every entry is checked against the files; a missing or
  broken generation falls back to the newest complete one, and an entry with
  nothing usable is reset (the next fetch issues again). Repairs are logged
  and audited as `error` events "direct cache repaired" (admins only).
- **Route53 zones** are verified against AWS; a failure is only a warning
  (on a first start AWS is usually not configured yet).
- **Certificate Transparency inventory** (architecture §31) is in memory
  only: it starts empty and the first refresh runs right after the broker
  is ready (a few seconds, `api.certspotter.com` must be reachable). Each
  start costs about two Cert Spotter queries per queried zone out of 10 per
  hour; several restarts within an hour can use them up, and the status page
  then shows the inventory as not available until the retry (15 minutes or
  Cert Spotter's `Retry-After`).

Shutdown (SIGTERM): `/healthz` turns 503, the listener stops accepting,
in-flight requests get `server.shutdown_grace`, background issuance work
gets the same grace and anything still running is left for the next start.

## Housekeeping

Once a minute the broker expires unfinalized orders (`scheduler.order_ttl`)
and compacts old ones, removes DNS-proxy challenges older than
`dns_proxy.challenge_ttl`, prunes settled budget events and deletes expired
sessions. Nothing needs to be scheduled from outside.

## Runbooks

### Provider circuit open

Symptoms: `tlsbroker_scheduler_circuit_open{provider} == 1`, the status page
and *Admin → Providers* show the provider `rate_limited` or `down` with a
retry-after; clients get `429 rateLimited` with `Retry-After`; the audit log
has a `provider_state` event (admins only).

1. Read the last error on *Admin → Providers*. `rate_limited` means the CA
   said so: wait; the broker reopens at the CA's Retry-After. `down` means
   transport errors or 5xx: check the CA's status page and the host's
   outbound connectivity (`docker compose logs` shows the errors).
2. There is no manual reset; after a `down` closure one probe request is let
   through and a success reopens the provider.
3. Renewals inside the emergency window fail over to the next enabled
   provider automatically. To move all issuance to the fallback, disable the
   provider in the configuration (`disabled: true`) and activate; enable it
   again later.

### Budget exhausted

Symptoms: `tlsbroker_scheduler_budget_remaining{kind=...}` near 0 (alert
`BrokerBudgetLow`), clients get `429 rateLimited` with a Retry-After of when
the window has room; *Admin → Providers* shows the bucket.

1. Find the consumer: *Audit* filtered by `order`/`issue` events, by source
   IP and names. A misconfigured client re-ordering in a loop is the usual
   cause; block it (remove its grant, or block the user) until fixed.
2. A share of every budget (`renewal_reserve_percent`) is kept for renewals,
   and ARI-qualified renewals at an ARI-exempt CA do not count, so existing
   certificates keep renewing.
3. Only if the broker's limits are below the CA's real ones, raise
   `providers[].limits` in the configuration. Never above the CA's limits: the
   budgets are what keep the CA from rate-limiting the whole broker.

### Zone unprotected (wildcard CAA warning)

Symptoms: a status page warning that the zone is unprotected and "no" in its
*Wildcard protected* column; DNS-proxy requests for wildcard names are denied with
`wildcard_unprotected`.

1. Copy the suggested CAA records from the status page (unpinned `issue`,
   `issuewild` with `accounturi=<the broker's account URL>`) into the zone in
   Route53 (or wherever the zone's CAA lives). Your own ACME clients that need
   wildcards (for example certbot hosts) get an `issuewild` line each, pinned
   with `accounturi=<their account URL>`; an unpinned `issuewild` keeps the
   zone unprotected.
2. Reload the status page until the zone's *Wildcard protected* column says
   "yes". The parameter name `accounturi` must be lower case, and the CA must
   be an enabled provider with `account_uri_honoured: true`.

### Broker cannot issue a zone's wildcards

Symptoms: a status page warning "CAA pins wildcards to other ACME accounts
only; the broker itself cannot issue ...", and "broker's account not pinned"
under the zone's verdict. The zone is protected (the DNS proxy keeps
working), but ACME proxy and direct-API wildcard orders fail at the CA.

1. Add an `issuewild` line pinned to the broker's account URL (status page,
   *CA accounts for CAA*). Account URLs must match exactly; a re-created CA
   account (lost `provider-account-key.*`) has a new URL and needs new
   records.

### LDAP down

Symptoms: LDAP users get 503 "The LDAP directory is unavailable" at login;
*Test LDAP* fails; the status page says "The last LDAP check (...) failed"
when the startup or activation check failed; existing sessions keep working
(sessions do not touch LDAP).

1. Log in as the local break-glass admin (`TLS_BROKER_LOCAL_ADMIN_USER`);
   it never needs LDAP.
2. Check the LDAP server and the bind password secret; fix the configuration
   or the secret in the UI and run *Test LDAP* (or let an LDAP user log in);
   a passing check clears the status page warning.
3. Without UI access at all, manage users from the command line:
   `tls-broker user set-role <name> admin`, `tls-broker user block <name>`,
   `tls-broker user unblock <name>` (`--local` for the break-glass record).
   Machine issuance (ACME, DNS proxy, direct) does not depend on LDAP.

### Disk full

Symptoms: 500 answers, `database is locked`/`disk I/O error` or "no space
left on device" in the logs, `tlsbroker_audit_write_failures_total`
increasing, `/healthz` 503 `{"reason":"database"}` when SQLite cannot be
read.

1. Free space on the volume holding `deploy/data`. The usual growth is
   `audit/` (set `audit.max_files` to cap retention, then restart) and
   backups left in `data/`.
2. Restart the broker once there is space; startup recovery repairs orders,
   DNS records and cache generations that failed half-way.
3. Audit events written while the disk was full are lost (the metric says how
   many); SQLite state is not, since every change is one transaction.

### Rotating a direct-mode key

When a device's key may be compromised: *Certificates* (as admin) → *Rotate
key* on the direct entry. The broker generates a new key, issues a new
certificate synchronously (ordinary CA budget) and makes it the active
generation; the device gets it on its next fetch (the `ETag` changes). The old
generation stays on disk until pruned. Revocation of the old certificate is
done with the CA directly if needed (the broker offers none).

### Rotating AWS credentials

- **Credentials as secrets** (`route53.access_key_id_secret` /
  `secret_access_key_secret`): create the new access key in IAM, set both
  secrets to the new values in *Admin → Secrets*; the Route53 client re-reads
  them within five minutes, no restart. Watch for successful DNS-01 (or
  `tlsbroker_dns01_failures_total` staying flat), then delete the old key in
  IAM.
- **Credentials from the environment** (`AWS_ACCESS_KEY_ID`, ... in `.env` or
  the inline compose file): create the new key, edit the file, `docker compose
  up -d` (recreates the container, graceful stop), then delete the old key.
- Changing `route53.region` or the secret names in the configuration rebuilds
  the client when the generation is activated, and the zones are verified
  again (a failure is logged as a warning).

### Certificate Transparency inventory stale

Symptoms: the status page says the certificates in managed zones are partly
out of date or not available; *Needs attention* names the zone and the
error; `tlsbroker_ct_zone_up{zone} == 0`.

1. "rate limited": Cert Spotter's 10 queries per hour are used up (restarts,
   or another client behind the same address). Wait; the inventory retries
   once after the `Retry-After` and then keeps its interval. Do not lower
   `ct_inventory.interval` to catch up.
2. Transport errors: check outbound HTTPS to `api.certspotter.com` from the
   host.
3. The previous data stays on the page while a zone fails. To stop all
   queries set `ct_inventory.disabled: true` (takes effect at activation).

### Publishing the user guide to Confluence

The user guide (`docs/guide`, shipped in the image) can be copied to
Confluence Server/Data Center by hand. Confluence holds a copy; the
repository stays the source, and every published page says so in an info
box at the top.

Once, add to the service's `environment` in the compose file (production:
`/srv/docker/tls-broker/compose.yaml`) and recreate the container with
`docker compose up -d`:

| Variable | Value |
|---|---|
| `TLS_BROKER_CONFLUENCE_URL` | base URL, for example `https://confluence.example.com` |
| `TLS_BROKER_CONFLUENCE_TOKEN` | personal access token of a user who may edit the root page and create pages below it (sent as `Authorization: Bearer`) |
| `TLS_BROKER_CONFLUENCE_PAGE_ID` | numeric ID of the root page (production: `123456`, "TLS Broker" in space `admin`) |

Then, from the compose directory:

```sh
docker compose exec tls-broker tls-broker docs publish --dry-run   # read only: prints the plan
docker compose exec tls-broker tls-broker docs publish
```

What it does:

- The root page gets the guide's index (`README.md`); its title stays as it
  is. Every page the index lists becomes a child page titled
  `TLS Broker: <its # title>` (Confluence titles are unique per space; the
  prefix keeps "Troubleshooting" and the like from colliding with other
  pages of the space).
- Child pages are found by title under the root; nothing is stored locally.
  Missing pages are created, changed pages updated (new version, comment
  `tls-broker <version>`), unchanged pages left alone. A body counts as
  unchanged when it matches the published one after normalization; the
  version in the info box alone is no change.
- The child pages are put in index order (Confluence's move API); a
  Confluence without it gets a warning and the order is left to you.
- The examples carry `server.external_url` of the active configuration
  generation instead of `https://broker.example.com`, as in the web UI;
  `--broker-url <url>` overrides it.
- Links between guide pages become Confluence page links (anchors to the
  headings work); links to other files of the repository become text naming
  the file.

What it never does: delete or rename pages, touch pages that are not the
root or its children (child pages that are not in the guide are listed and
left alone), or create a page whose title another page of the space already
has (the run stops before writing anything). The broker itself never reads
these variables; the token is never printed.

Errors name the cause: missing variables, a rejected token (401), a user who
may read but not edit (403), a root page that does not exist or is hidden
(404). A version conflict (someone edited the page meanwhile) is retried once
after reading the page again; edits made in Confluence are overwritten by the
next publish.

Options: `--out <dir>` also writes each page's storage-format XHTML for
inspection; `--docs <dir>` reads the guide from another directory (outside
the image, for example `docs/guide` in a checkout).

### Other checks

- `docker compose ps` shows `healthy` once ready; `docker compose logs` is
  JSON (`TLS_BROKER_LOG_LEVEL=debug` for more).
- `tls-broker config validate <file>` checks a YAML file offline, including
  missing secrets.
- Metrics and alert rules: `docs/observability.md`.
