# Documentation

## Guides

Task-oriented pages for people who need certificates. The broker's web
interface shows exactly these pages under **Documentation**.

- [User guide](guide/README.md): getting started, the web interface, the
  ACME proxy, the DNS proxy, direct download, troubleshooting and the API
  reference.

## Reference

How each part behaves in detail, for operators and for anyone integrating
with the broker.

- [ACME proxy](acme-proxy.md): the downstream ACME server, client
  compatibility.
- [DNS proxy](dns-proxy.md): `/dns/present` and `/dns/cleanup`.
- [Direct certificate API](direct-api.md): `/cert/<name>`, file formats,
  renewal.
- [Authorization](authorization.md): client access (IP grants), the DNS gate,
  CAA.
- [Authentication](authentication.md): LDAP, the local admin, sessions.
- [Web UI](ui.md): pages, roles and the first start.
- [Configuration](configuration.md): environment and YAML.
- [Deployment](deployment.md): compose, reverse proxy, upgrades.
- [Operations](operations.md): backup, restore, recovery, runbooks.
- [Observability](observability.md): audit log, metrics, health.
- [Rate limits and admission](rate-limits.md).
- [Upstream CA providers](providers.md).
- [Route53 DNS-01 engine](dns01.md).

## Engineering

- [Architecture](../architecture.md): what the system does and why.
- [Implementation plan](plan.md): packages, contracts, build order.
- [Issuance engine](issuance.md).
- [Data model](data-model.md).
- [Development](development.md): building, testing, shipping the docs.
