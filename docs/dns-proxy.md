# DNS proxy

In this mode the client stays its own ACME client and talks to the public CA
itself. It only hands the DNS-01 TXT handling to the broker: it asks the
broker to publish a TXT value in Route53, waits for the answer, completes the
challenge with its CA, and asks the broker to remove the value. Code:
`internal/dnsproxy`; the engine behind it is described in `dns01.md`.

## When to use it, and why it is secondary

Use it only when a system must keep its own ACME client and its own CA
account and cannot use the ACME proxy (`acme-proxy`) or the direct API:
appliances with a fixed client, tools that can run a DNS hook but cannot
change the directory URL, or one-off wildcard needs of an operator.

It is secondary because the broker is blind to what happens next:

- The client orders certificates from the CA directly. **The broker cannot
  protect upstream CA rate limits** (new orders, duplicate certificates,
  failed validations). The only brake is the per-source limit on how many
  challenges one address may create.
- The broker cannot cache, dedupe, schedule renewals by ARI or fail over to
  another CA.
- A TXT value at `_acme-challenge.N` validates `*.N` as well as `N`, so the
  gate has to close the implicit wildcard (below).

Prefer the ACME proxy or the direct API wherever possible.

## Grant requirements

`/dns/present` uses the normal gate in mode `dnsproxy` (see
`authorization.md`). The identifier is `name` or `*.name`; both publish at
`_acme-challenge.name`. A request in the fqdn form
(`_acme-challenge.name`) is gated as identifier `name`.

| Situation | Result |
|---|---|
| identifier outside the managed zones | `404`, the gate is not asked |
| enabled grant with `wildcard=true` for the source | allowed (`ip_grant`) |
| ordinary grant, non-wildcard identifier | allowed only if the CAA condition holds |
| no grant, name resolves to the source, non-wildcard | allowed only if the CAA condition holds (`dns_ip_match`) |
| wildcard identifier without a wildcard grant | `403 wildcard_grant_required` |
| non-wildcard allowed by grant or DNS, CAA does not close `*.N` | `403 wildcard_unprotected` |
| name does not resolve to the source | `403 dns_mismatch` |
| resolvers failed | `403 dns_failure` (retry) |

**The CAA condition.** Without a wildcard grant the request is accepted only
when public CAA already stops every foreign ACME account from obtaining
`*.N`: the effective CAA RRset of `N` must have `issuewild` values that are
`;` or name an enabled provider pinned with `accounturi` to the broker's own
account (or, with no `issuewild`, `issue` values judged the same way). That
is what makes it safe to publish a TXT the broker cannot attribute to `N` or
`*.N`. Ready-to-publish records are in `authorization.md`. Note the
consequence for your own client: with such CAA records a client of this mode
can only get a certificate from the CA account the broker pins, so a client
needing its own account needs a `wildcard=true` grant and a matching CAA
policy of its own.

Hooks for `*.N` certificates normally pass the base name `N` (acme.sh and
Certbot both give the base name, and the fqdn form can only express `N`); the
gate then applies the rules for `N`. Send identifier `*.N` explicitly only to
require a wildcard grant.

## API

All endpoints are JSON over HTTP(S) on the broker's normal listener. The
caller is identified by its source IPv4 address, nothing else; there are no
credentials. Request bodies are read as JSON whatever their `Content-Type`
(so `curl -d` works without `-H`). Errors are `application/problem+json`.

`present` and `cleanup` each take two body forms:

- **fqdn form** `{"fqdn":"_acme-challenge.foo.example.com.","value":"..."}`:
  what the stock acme.sh `dns_acmeproxy` and lego `httpreq` hooks send. The
  `fqdn` is the challenge record, `_acme-challenge.<name>` with or without the
  trailing dot, and means identifier `<name>` (never a wildcard; see "Grant
  requirements"). Cleanup is by record and value, so the client keeps no
  state.
- **identifier form** `{"identifier":"foo.example.com","value":"..."}`, and
  cleanup by the returned `challenge_id`.

### `POST /dns/present`

```sh
curl -sS https://broker.lan/dns/present \
  -d '{"fqdn":"_acme-challenge.foo.example.com.","value":"gfj9Xq-Wz7jbo5ZFFYAj7RRsbFqS5ywCRcPb4Phv0kE"}'
# or
curl -sS https://broker.lan/dns/present \
  -d '{"identifier":"foo.example.com","value":"gfj9Xq-Wz7jbo5ZFFYAj7RRsbFqS5ywCRcPb4Phv0kE"}'
```

```json
{"challenge_id":"3fa85f64c5f84a8f9d3e0a4e2e1b7c11","record":"_acme-challenge.foo.example.com","value":"gfj9Xq-Wz7jbo5ZFFYAj7RRsbFqS5ywCRcPb4Phv0kE"}
```

The call returns `201` only after the exact value is visible through the
broker's public resolver (it can take up to `dns_proxy.present_timeout`).
Your client may then ask its CA to validate. Rules:

- Exactly one of `identifier` and `fqdn` (`400` for both or neither). Either
  is normalized (case, trailing dot, IDNA). `value` is the value your ACME
  client computed: usually 43 base64url characters, but any 1 to 255
  printable ASCII characters without space, `"` or `\` are accepted.
- It is idempotent: the same source, record and value return the same
  `challenge_id` (again `201`) and do not count against the limit, whichever
  form was used.
- Several values at one record coexist (for example `N` and `*.N` in one
  order). Cleaning one never removes another.
- Unknown JSON fields, trailing data and bodies over 4 KiB are rejected.

### `POST /dns/cleanup`

By record and value:

```sh
curl -sS https://broker.lan/dns/cleanup \
  -d '{"fqdn":"_acme-challenge.foo.example.com.","value":"gfj9Xq-Wz7jbo5ZFFYAj7RRsbFqS5ywCRcPb4Phv0kE"}'
```

```json
{"fqdn":"_acme-challenge.foo.example.com.","value":"gfj9Xq-Wz7jbo5ZFFYAj7RRsbFqS5ywCRcPb4Phv0kE"}
```

It removes the caller's own active challenges with that record and value and
answers `200` with the body above. It is idempotent: when there is nothing to
remove (already cleaned up, swept, never presented, or presented by another
source address, whose value is left in place) it still answers `200`, so a
retried hook never fails. Only the source address that presented can remove
a value.

By challenge ID:

```sh
curl -sS https://broker.lan/dns/cleanup \
  -d '{"challenge_id":"3fa85f64c5f84a8f9d3e0a4e2e1b7c11"}'
# 204 No Content
```

or `DELETE /dns/challenges/<challenge_id>`. Only the source address that
presented may clean up (`403` otherwise). It is idempotent: a challenge
that is already cleaned up returns `204` again. An unknown or already pruned
ID returns `404`. It removes only that challenge's own value. A body with
both `challenge_id` and `fqdn`/`value` is rejected (`400`).

### `GET /dns/challenges`

Lists the caller's active (not yet cleaned up) challenges:

```sh
curl -sS https://broker.lan/dns/challenges
```

```json
{"challenges":[{"challenge_id":"3fa8...","record":"_acme-challenge.foo.example.com","value":"gfj9...","state":"ready","created_at":"2026-10-02T10:11:00Z"}]}
```

Use it to find the ID after a crashed hook.

## Clients

No hook script is needed: acme.sh and lego ship a hook that speaks the fqdn
form, and Certbot needs two one-line `curl` hooks. Replace `broker.lan` with
your broker's name; the client host must be allowed by the gate (above) and
must trust the broker's TLS certificate. Hooks for `*.N` pass the record of
`N`, so a wildcard order is gated as `N` (see "Grant requirements").
`make compat` runs the acme.sh and Certbot commands below (the Certbot hooks
verbatim) against Pebble, including renewal and cleanup.

### acme.sh

The built-in `dns_acmeproxy` hook. Leave `ACMEPROXY_USERNAME` and
`ACMEPROXY_PASSWORD` unset: the broker trusts the source address.

```sh
export ACMEPROXY_ENDPOINT=https://broker.lan/dns
acme.sh --issue --dns dns_acmeproxy --dnssleep 0 -d foo.example.com
```

acme.sh stores the endpoint with the account, so renewals need nothing more.
`--dnssleep 0` skips acme.sh's own propagation check, which is redundant:
`present` returns only once the value is publicly visible.

### Certbot

```sh
certbot certonly --manual --preferred-challenges dns \
  --manual-auth-hook 'curl -sSf https://broker.lan/dns/present -d "{\"fqdn\":\"_acme-challenge.$CERTBOT_DOMAIN.\",\"value\":\"$CERTBOT_VALIDATION\"}"' \
  --manual-cleanup-hook 'curl -sSf https://broker.lan/dns/cleanup -d "{\"fqdn\":\"_acme-challenge.$CERTBOT_DOMAIN.\",\"value\":\"$CERTBOT_VALIDATION\"}"' \
  -d foo.example.com
```

The single quotes keep the variables for Certbot's hook shell, which expands
them. `-f` makes a refusal fail the hook (and the run); `-S` prints why.
Certbot stores both hooks in the renewal configuration, so `certbot renew`
reuses them. For `*.example.com` plus `example.com` in one order Certbot runs
the hook twice with the same `CERTBOT_DOMAIN` and different values; both
coexist.

### lego

The built-in `httpreq` provider in its default (JSON) mode:

```sh
HTTPREQ_ENDPOINT=https://broker.lan/dns \
  lego --email ops@example.com --dns httpreq -d foo.example.com run
```

(lego v4 command syntax.) Leave `HTTPREQ_MODE` unset (`RAW` sends a
different body) and `HTTPREQ_USERNAME`/`HTTPREQ_PASSWORD` unset. lego
`httpreq` sends the same requests as acme.sh but is not part of `make compat`.

### Anything else

Any client that can run a command per challenge works with the two `curl`
calls of the Certbot hooks above: `POST /dns/present` with
`{"fqdn":"_acme-challenge.<name>.","value":"<txt>"}` before validation, the
same body to `/dns/cleanup` afterwards.

## Limits and housekeeping

| Setting (`dns_proxy`) | Effect |
|---|---|
| `present_timeout` | upper bound of one present call, including propagation |
| `max_per_source` | `count` new challenges per `window` per source address; `count: 0` disables. Repeats of an existing challenge are free |
| `challenge_ttl` | a value that is still published this long after creation is removed by the broker's periodic sweep, so a crashed client cannot leave TXT records behind |

The limiter is in memory and starts empty after a restart. The sweep only
removes challenges of DNS-proxy sources; challenges of the broker's own
orders are never touched by it.

## Errors

| Status | When | Notes |
|---|---|---|
| `200` | cleanup by `fqdn` and `value` done, or nothing left to remove | body `{"fqdn","value"}` |
| `201` | value published and visible | |
| `204` | cleanup by `challenge_id` done (or already done) | |
| `400` | bad JSON, unknown field, both or neither of `identifier`/`fqdn`, `fqdn` not `_acme-challenge.<name>`, invalid identifier, bad `value`, missing `challenge_id` | `malformed` / `rejectedIdentifier` |
| `403` | gate denial, wrong owner on cleanup by `challenge_id`, source not IPv4 | detail starts with `denied:` and the reason, for example `denied: wildcard_unprotected` |
| `404` | identifier outside managed zones, unknown challenge | |
| `413` | body over 4 KiB | |
| `429` | per-source limit | `Retry-After` in seconds until a slot frees |
| `503` | gate or Route53 unavailable | `Retry-After`; try again, the call is idempotent |
| `504` | value not visible before `present_timeout` | the broker removed the value again; retry |

Every present and cleanup, including denials and sweeps, is audited with
mode `dnsproxy`, the decision, the reason and the grant ID (`dns_present` /
`dns_cleanup` events; see `observability.md`; a cleanup by `fqdn` that found
nothing of the caller's is recorded with reason `nothing_to_clean`) and counted in
`tlsbroker_requests_total{mode="dnsproxy"}` and the gate-decision metric.
