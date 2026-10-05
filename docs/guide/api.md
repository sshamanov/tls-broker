# API reference

Every public endpoint of the broker, at `https://broker.example.com`. This is
a summary; the deep references are in the repository's `docs/` directory
(linked below).

## Who may call what

Certificate requests carry **no credentials**. The broker decides from the
IPv4 address the request comes from (behind the broker's reverse proxy: the
address the proxy reports):

- an enabled client access entry covers the address (wildcards need an entry
  that allows them), or
- every requested name resolves in public DNS to that address (never enough
  for a wildcard).

Every name must be inside a managed zone. The decision is made on every
request, also for a certificate the broker already has. See
[Getting started](getting-started.md#getting-access).

| Endpoints | Who |
|---|---|
| `/acme/...`, `/dns/...`, `/cert/...` | any address, decided per request as above |
| `/healthz` | anyone (the operator may restrict it at the reverse proxy) |
| `/metrics` | anyone the reverse proxy lets through (normally only the monitoring host) |
| `/ui/` | the web interface; login required (`/ui/login`) |

## ACME proxy

Directory: `https://broker.example.com/acme/directory`. A standard ACME v2
server (RFC 8555) for certbot, acme.sh, lego and similar clients; how to use
it: [ACME proxy guide](acme-proxy.md).

| Method and path | Purpose |
|---|---|
| `GET /acme/directory` | the directory: URLs of the resources below |
| `HEAD`, `GET /acme/new-nonce` | a fresh `Replay-Nonce` |
| `POST /acme/new-account` | create or look up the account for a key; accounts carry no permissions |
| `POST /acme/acct/{id}`, `POST /acme/acct/{id}/orders` | read, update or deactivate the account; its (always empty) order list |
| `POST /acme/key-change` | roll the account key over |
| `POST /acme/new-order` | create an order; held while waiting for an admission slot (up to 20 s by default), then `ready` |
| `POST /acme/authz/{order}/{n}` | an authorization; always `valid` (the broker proves control itself) |
| `POST /acme/chall/{order}/{n}` | its synthetic `dns-01` challenge, already `valid` |
| `POST /acme/order/{id}` | poll the order (`Retry-After` while `processing`) |
| `POST /acme/order/{id}/finalize` | send the CSR; answers `valid` or `processing` |
| `POST /acme/cert/{id}` | download the chain: leaf and intermediates, no root |
| `GET /acme/renewal-info/{certID}` | renewal information (ARI, RFC 9773) from the issuing CA |

All `POST`s are JWS-signed (POST-as-GET for reads). Not offered:
`/acme/revoke-cert` (answers `403`), `newAuthz`, http-01 or tls-alpn-01
validation, alternate chains. Errors are ACME problem documents; see
[Troubleshooting](troubleshooting.md). Deep reference:
[ACME proxy reference](../acme-proxy.md).

## DNS proxy

For clients that keep their own ACME account and only need the DNS-01
`TXT` record published ([DNS proxy guide](dns-proxy.md)). JSON request
bodies (no `Content-Type` needed, at most 4 KiB), JSON or problem answers.

| Method and path | Purpose |
|---|---|
| `POST /dns/present` | publish a value; answers `201` once it is publicly visible |
| `POST /dns/cleanup` | remove a value you published |
| `GET /dns/challenges` | list your values that are still published |
| `DELETE /dns/challenges/{id}` | remove one value by its ID |

`present` and `cleanup` accept two body forms:

```json
{"fqdn": "_acme-challenge.www.example.com.", "value": "gfj9Xq-Wz7jbo5ZFFYAj7RRsbFqS5ywCRcPb4Phv0kE"}
```

```json
{"identifier": "www.example.com", "value": "gfj9Xq-Wz7jbo5ZFFYAj7RRsbFqS5ywCRcPb4Phv0kE"}
```

The `fqdn` form is what the stock acme.sh `dns_acmeproxy` and lego `httpreq`
hooks send; cleanup takes the same body and answers `200` even when there is
nothing left to remove. The `identifier` form returns a `challenge_id`;
clean up with `{"challenge_id": "..."}` (`204`) or
`DELETE /dns/challenges/{id}`. Repeating a `present` is harmless (same ID,
`201` again). Only the address that published a value can remove it.

| Status | Meaning |
|---|---|
| `200`, `201`, `204` | done (cleanup, present, cleanup by ID) |
| `400` | malformed body or name |
| `403` | refused; the detail is `denied: <reason>` |
| `404` | name outside the managed zones, or unknown challenge ID |
| `413` | body over 4 KiB |
| `429` | too many new values from your address; see `Retry-After` |
| `503` | DNS or the access check unavailable; retry |
| `504` | the value did not become visible in time; retry |

Deep reference: [DNS proxy reference](../dns-proxy.md).

## Direct download

`GET` (or `HEAD`) only ([direct download guide](direct.md)).

| Path | Returns |
|---|---|
| `/cert/{name}` | tar with `privkey.pem` and `fullchain.pem` for `name` |
| `/cert/wildcard/{base}` | the same for `*.base` (no `*` in the URL) |

Every `200` has an `ETag`; send it in `If-None-Match` to get `304 Not
Modified` while the certificate is unchanged. `HEAD` gives the headers
without the body. Answers are never cached by proxies (`Cache-Control:
no-store`).

| Status | Meaning |
|---|---|
| `200` | the certificate (a valid cached one is served even while the CAs are down) |
| `304` | unchanged since the `ETag` you sent |
| `403` | refused (`unauthorized`): no access for this address, or a wildcard without an entry that allows wildcards |
| `404` | invalid name, outside the managed zones, or a malformed path (`rejectedIdentifier`) |
| `405` | a method other than `GET` or `HEAD` |
| `429` | nothing valid cached and issuance is rate limited; see `Retry-After` |
| `503` | nothing valid cached and issuance is not possible now; see `Retry-After` |

Deep reference: [direct API reference](../direct-api.md).

## Health and metrics

| Method and path | Returns |
|---|---|
| `GET`, `HEAD /healthz` | `200 {"status":"ok"}` when the broker can take traffic, `503` with a status while starting, shutting down or when its database fails; never reflects the CAs' health |
| `GET /metrics` | Prometheus metrics: requests, issuance, rate-limit budgets, certificate expiry |

Deep reference: [observability reference](../observability.md).
