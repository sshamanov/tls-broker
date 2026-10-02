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

> Status: under construction. The skeleton (contracts, tooling) is in place;
> the service itself is being built in the order given in `docs/plan.md`.

## Quick start

```sh
cd deploy
cp .env.example .env        # set the break-glass admin user and password
mkdir -p data
docker compose up -d
```

The container uses host networking and keeps all state in `deploy/data`. Put
nginx in front for TLS and for passing the real client address. On first start
the broker writes a default configuration; log in to the UI as the break-glass
admin to add Route53 zones, providers and LDAP settings.

## Documentation

- [`architecture.md`](architecture.md) — what the system does and why.
- [`docs/plan.md`](docs/plan.md) — package layout, contracts, build order.
- [`docs/development.md`](docs/development.md) — building and testing.
