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

## Client hooks

Set `BROKER` to the broker's base URL. Both hooks use only `curl` and `sed`.

### acme.sh (`dns_broker.sh`)

Save as `~/.acme.sh/dnsapi/dns_broker.sh`, then
`export DNS_BROKER_URL=https://broker.lan` and issue with `--dns dns_broker`
(add `--dnssleep 0`: the broker already waited for propagation).

```sh
#!/usr/bin/env sh
# acme.sh DNS API hook for the TLS broker's DNS proxy.
# Usage: DNS_BROKER_URL=https://broker.lan acme.sh --issue --dns dns_broker -d foo.example.com

dns_broker_add() {
  fulldomain=$1   # _acme-challenge.foo.example.com
  txtvalue=$2
  _broker_init || return 1
  domain=${fulldomain#_acme-challenge.}
  _info "Asking the broker to publish the challenge for $domain"
  resp=$(curl -sS -m 300 -w '\n%{http_code}' -X POST "$DNS_BROKER_URL/dns/present" \
    -H 'Content-Type: application/json' \
    -d "{\"identifier\":\"$domain\",\"value\":\"$txtvalue\"}") || {
    _err "broker unreachable"; return 1; }
  code=$(printf '%s' "$resp" | tail -n 1)
  body=$(printf '%s' "$resp" | sed '$d')
  if [ "$code" != 201 ]; then
    _err "broker refused ($code): $body"
    return 1
  fi
  id=$(printf '%s' "$body" | sed -n 's/.*"challenge_id":"\([^"]*\)".*/\1/p')
  mkdir -p "$_broker_state" && printf '%s' "$id" >"$_broker_state/$txtvalue"
}

dns_broker_rm() {
  fulldomain=$1
  txtvalue=$2
  _broker_init || return 1
  f="$_broker_state/$txtvalue"
  [ -f "$f" ] || { _info "no broker challenge recorded for this value"; return 0; }
  code=$(curl -sS -m 60 -o /dev/null -w '%{http_code}' -X DELETE \
    "$DNS_BROKER_URL/dns/challenges/$(cat "$f")")
  case $code in
    204|404) rm -f "$f" ;;   # 404: already gone
    *) _err "broker cleanup failed ($code)"; return 1 ;;
  esac
}

_broker_init() {
  DNS_BROKER_URL="${DNS_BROKER_URL:-$(_readaccountconf_mutable DNS_BROKER_URL)}"
  if [ -z "$DNS_BROKER_URL" ]; then
    _err "Set DNS_BROKER_URL, for example https://broker.lan"
    return 1
  fi
  _saveaccountconf_mutable DNS_BROKER_URL "$DNS_BROKER_URL"
  _broker_state="${LE_WORKING_DIR:-$HOME/.acme.sh}/dns_broker_state"
}
```

### Certbot

Certbot gives the base name in `CERTBOT_DOMAIN` (without `*.`), the value in
`CERTBOT_VALIDATION`, and passes the output of the auth hook to the cleanup
hook as `CERTBOT_AUTH_OUTPUT`, so the challenge ID needs no state file.

`/etc/letsencrypt/broker-auth.sh`:

```sh
#!/bin/sh
set -eu
BROKER=${BROKER:-https://broker.lan}
resp=$(curl -sS -m 300 -w '\n%{http_code}' -X POST "$BROKER/dns/present" \
  -H 'Content-Type: application/json' \
  -d "{\"identifier\":\"$CERTBOT_DOMAIN\",\"value\":\"$CERTBOT_VALIDATION\"}")
code=$(printf '%s' "$resp" | tail -n 1)
body=$(printf '%s' "$resp" | sed '$d')
if [ "$code" != 201 ]; then echo "broker refused ($code): $body" >&2; exit 1; fi
# stdout becomes CERTBOT_AUTH_OUTPUT: only the challenge ID
printf '%s\n' "$body" | sed -n 's/.*"challenge_id":"\([^"]*\)".*/\1/p'
```

`/etc/letsencrypt/broker-cleanup.sh`:

```sh
#!/bin/sh
set -eu
BROKER=${BROKER:-https://broker.lan}
[ -n "${CERTBOT_AUTH_OUTPUT:-}" ] || exit 0
code=$(curl -sS -m 60 -o /dev/null -w '%{http_code}' -X DELETE \
  "$BROKER/dns/challenges/$CERTBOT_AUTH_OUTPUT")
case $code in 204|404) ;; *) echo "broker cleanup failed ($code)" >&2; exit 1 ;; esac
```

```sh
certbot certonly --manual --preferred-challenges dns \
  --manual-auth-hook /etc/letsencrypt/broker-auth.sh \
  --manual-cleanup-hook /etc/letsencrypt/broker-cleanup.sh \
  -d foo.example.com
```

For `*.example.com` plus `example.com` in one order Certbot runs the hook
twice with the same `CERTBOT_DOMAIN` and different values; both coexist.
Renewals reuse the stored hooks.

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
