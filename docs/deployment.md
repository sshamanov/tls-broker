# Deployment

The broker is one container (`tls-broker`, distroless, non-root, static
binary) with host networking and one data volume. Put nginx (or Caddy) on the
same host in front of it for TLS and for passing the real client address.

## Files in `deploy/`

| File | Use |
|---|---|
| `Dockerfile` | Builds the image with `tls-broker` (entrypoint) and the development-only `mockdoh`. `make image` tags it `tls-broker:local`; CI publishes `ghcr.io/sshamanov/tls-broker`. |
| `compose.yaml` | Shipping compose: settings from `.env` next to it (`env_file`). |
| `.env.example` | Template for `.env` (never commit `.env`). |
| `compose.prod.example.yaml` | Template with the environment **inline**, for hosts where one file is easier than two. Copy it to `compose.prod.yaml` (production) or `compose.test.yaml` (LAN test box); both copies are gitignored because they hold credentials. |
| `nginx.example.conf` | nginx front: TLS termination, `X-Real-IP`, long timeouts for held requests, `/metrics` restricted. |
| `caddy.example/Caddyfile` | Caddy front for a LAN test with `tls internal` (Caddy's own CA). |

## Compose

```sh
cd deploy
cp .env.example .env      # set the break-glass admin, PUID/PGID, admins
mkdir -p data && sudo chown 1000:1000 data   # PUID:PGID must own it
docker compose up -d
docker compose logs -f tls-broker
```

or, with everything inline:

```sh
cp deploy/compose.prod.example.yaml deploy/compose.prod.yaml   # edit it
docker compose -f deploy/compose.prod.yaml up -d
```

The service runs with `network_mode: host`, `restart: unless-stopped`, the
configured `user`, and `stop_grace_period: 30s` (longer than the default
`server.shutdown_grace` of 25 s, so in-flight requests and issuance drain on
`docker compose stop`). The image's health check runs `tls-broker
healthcheck`, which asks `/healthz` on `TLS_BROKER_LISTEN` (a wildcard host is
probed on 127.0.0.1); `docker ps` shows `healthy` once startup recovery has
finished.

**Local test deployment.** `deploy/compose.test.yaml` (gitignored, built from
the prod example, holding live AWS credentials inline) runs the locally built
image `tls-broker:local` with data in `deploy/data-test`:

```sh
make image
mkdir -p deploy/data-test
make run-test             # docker compose -f deploy/compose.test.yaml up -d
docker compose -f deploy/compose.test.yaml logs -f
docker compose -f deploy/compose.test.yaml down
```

## Environment

Read once at start; a change needs `docker compose up -d` (which recreates
the container). Full table in `docs/configuration.md`.

| Variable | Typical value |
|---|---|
| `TLS_BROKER_DATA_DIR` | `/data` (set by the image) |
| `TLS_BROKER_LISTEN` | `127.0.0.1:8080` behind a local proxy; `0.0.0.0:8080` only for a test box without one |
| `TLS_BROKER_ADMINS` | LDAP usernames that are always admin |
| `TLS_BROKER_LOCAL_ADMIN_USER` / `_PASSWORD` | break-glass administrator (plain or bcrypt; `$` as `$$` in compose files) |
| `TLS_BROKER_LOG_LEVEL` | `info` |
| `TLS_BROKER_DOH_ENDPOINTS` | **empty in production** (development-only mocked DNS gate) |
| `TLS_BROKER_CONFLUENCE_URL`, `_TOKEN`, `_PAGE_ID` | optional: only for copying the user guide to Confluence by hand (`tls-broker docs publish`, see `docs/operations.md`); the broker ignores them |
| `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY` (or other AWS chain settings) | optional: Route53 credentials through the standard AWS chain when the configuration names no Route53 secrets; the region always comes from `route53.region` |

## Data volume

Everything the broker keeps is under the data root (architecture §22):

```text
/data/
  config/      000001.yaml 000002.yaml ... current -> 00000N.yaml   (0700)
  secrets/     route53-*, ldap-bind-password, eab.*, provider-account-key.*,
               provider-account-url.*                                (0700, files 0600)
  state.db     SQLite (plus state.db-wal / state.db-shm while running)   (0600)
  certs/       direct-mode cache: <identifier>/generations/<n>/{privkey,fullchain}.pem
               and <identifier>/current -> generations/<n> (wildcards as _wildcard.<base>)
  audit/       audit JSONL, rotated by day and size
```

The directory must be writable by the container user (`PUID:PGID`, default
1000:1000). Back up as described in `docs/operations.md`.

## First start

1. Start with `TLS_BROKER_LOCAL_ADMIN_USER`/`_PASSWORD` set. The broker writes
   configuration generation 000001 from the defaults and is ready within a
   second or two (`docker compose logs` shows `tls-broker ready`).
2. Open `https://broker.example.com/ui/` and log in as the local admin. Then
   follow "First start" in `docs/ui.md`: secrets (Route53 keys unless the AWS
   environment chain is used, EAB keys, LDAP bind password), configuration
   (`server.external_url`, `server.trusted_proxies`, zones, providers, LDAP),
   activate, then CAA records with the account URLs the status page shows.
3. Optional, without the UI: write the YAML to the data volume and activate it
   from the container, then restart (a running broker only picks up
   generations activated through the UI):

   ```sh
   docker compose exec tls-broker tls-broker config validate /data/new.yaml
   docker compose exec tls-broker tls-broker config apply /data/new.yaml
   docker compose restart tls-broker
   ```

**`sessions.cookie_secure`** defaults to `auto`: the session cookie is marked
Secure when the login arrived over HTTPS (directly, or through a trusted
proxy whose `X-Forwarded-Proto` says so), and not when it arrived over plain
HTTP, so a test box without a TLS front works out of the box. Set `always`
behind nginx/Caddy with HTTPS if you want the cookie Secure even when a
request slips in over HTTP (with `always` on plain HTTP the browser never
sends the cookie back and every login appears to fail silently). `never` is
for debugging only. Generations written by earlier versions with `true` /
`false` are read as `always` / `never`.

## Reverse proxy

The broker trusts the client address header only from `server.trusted_proxies`
and only the single header named by `server.real_ip_header`; it never reads
`X-Forwarded-For`. For a proxy on the same host:

```yaml
server:
  external_url: https://broker.example.com   # what clients use; ACME URLs are built from it
  trusted_proxies: [127.0.0.1]
  real_ip_header: X-Real-IP
```

- **nginx** (`deploy/nginx.example.conf`): terminates TLS, sets `X-Real-IP
  $remote_addr` and `X-Forwarded-Proto`, clears `X-Forwarded-For`, keeps
  `proxy_read_timeout` at 6 minutes (ACME finalize and `/cert/` issuance hold
  requests for up to `direct.issue_timeout`/`dns_proxy.present_timeout`, 4 min
  by default), and allows `/metrics` only from the monitoring network.
- **Caddy** (`deploy/caddy.example/Caddyfile`): the same for a LAN test with
  `tls internal`. Clients must trust Caddy's root certificate (certbot:
  `REQUESTS_CA_BUNDLE`, acme.sh: `--ca-bundle`).

The broker's own server timeouts (`server.read_timeout`, `write_timeout`) and
the audit rotation settings are read at start; change them in the UI and
restart. Everything else in the configuration applies when it is activated.

## Upgrading

```sh
docker compose pull            # or: make image, for the local tag
docker compose up -d           # stops gracefully (SIGTERM, 30 s), starts the new image
docker compose logs -f tls-broker
```

Take a backup first (`docs/operations.md`). The database schema is migrated
forward automatically at start; a database written by a newer version is
refused, so downgrading needs the backup taken before the upgrade. Interrupted
orders, DNS-01 records and direct-cache generations are repaired by startup
recovery; ACME clients retry on their own.
