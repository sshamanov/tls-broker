# tls-broker

A central TLS broker for LAN systems. One Go daemon sits between internal
machines and public certificate authorities (Let's Encrypt first, alternates as
fallback), answers DNS-01 through Route53, and protects the upstream CA rate
limits. It offers three ways to get a publicly trusted certificate:

- **ACME proxy** — point an unmodified ACMEv2 client (certbot, acme.sh) at
  `https://broker.example.com/acme/directory`. No hooks, no DNS credentials;
  the client keeps its private key.
- **DNS proxy** — a client that runs its own ACME flow delegates the DNS-01 TXT
  record to the broker (`POST /dns/present`, `POST /dns/cleanup`).
- **Direct certificate API** — `GET /cert/<name>` returns a tar with
  `privkey.pem` and `fullchain.pem` for devices that can do little more than
  `curl | tar`.

Machines are authorized by source IP: an explicit IP grant, or the requested
name resolving to the requester's address. Humans manage grants, configuration
and audit views in an LDAP-backed web UI.

## Quick start

```sh
cd deploy
cp .env.example .env        # set the break-glass admin user and password
mkdir -p data && sudo chown 1000:1000 data
docker compose up -d
docker compose logs -f tls-broker   # wait for "tls-broker ready"
```

The container uses host networking, listens on `127.0.0.1:8080` and keeps all
state in `deploy/data`. Put nginx (`deploy/nginx.example.conf`) or Caddy in
front for TLS and the real client address. On first start the broker writes a
default configuration; log in at `/ui/` as the break-glass admin to add
secrets, Route53 zones, providers and LDAP settings, then copy the account
URLs from the status page into your CAA records. The session cookie is marked
Secure only for logins that arrived over HTTPS, so a plain-HTTP test box
works without configuration (`sessions.cookie_secure: auto`).

From source: `make image` builds `tls-broker:local`; `make build`
builds `bin/tls-broker`. Inside the container `tls-broker help` lists the
maintenance commands (backup, config validate/apply, user roles and blocks).

## Documentation

[`docs/README.md`](docs/README.md) is the full index.

- [`docs/guide/`](docs/guide/README.md) — the user guide: getting access, the
  three modes with certbot, acme.sh and curl, troubleshooting, API summary.
  The web UI shows the same pages under Documentation.
- [`architecture.md`](architecture.md) — what the system does and why.
- [`docs/deployment.md`](docs/deployment.md) — compose, environment, reverse proxy, upgrades.
- [`docs/operations.md`](docs/operations.md) — backup, restore, recovery, runbooks.
- [`docs/configuration.md`](docs/configuration.md) — environment and YAML reference.
- [`docs/ui.md`](docs/ui.md) — the web UI and first-start walkthrough.
- [`docs/acme-proxy.md`](docs/acme-proxy.md), [`docs/dns-proxy.md`](docs/dns-proxy.md),
  [`docs/direct-api.md`](docs/direct-api.md) — the three issuance modes.
- [`docs/observability.md`](docs/observability.md) — audit log, metrics, health.
- [`docs/plan.md`](docs/plan.md) — package layout, contracts, build order.
- [`docs/development.md`](docs/development.md) — building and testing.
