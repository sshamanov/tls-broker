# ACME proxy (downstream ACME server)

The clean ACME proxy is the broker's primary mode (architecture §3.1). Hosts
on the LAN run an ordinary ACMEv2 client — Certbot or acme.sh — pointed at the
broker instead of at Let's Encrypt. They need no DNS credentials and no hooks:
the broker decides from the source address whether the host may have the
names, proves control upstream through Route53 DNS-01 itself, and hands back
the real certificate issued by the upstream CA for the client's own key.

Code: `internal/acmesrv`. Related: `docs/authorization.md` (the gate),
`docs/rate-limits.md` (admission and `Retry-After`), `docs/providers.md`
(upstream CAs).

## Directory URL

```text
https://broker.example.com/acme/directory
```

The base is `server.external_url` from the configuration plus `/acme`. Every
URL the broker returns is absolute and built from that setting, read on every
request, so it must be the URL clients actually use (the nginx front end's
name and scheme). The broker must be reached over https: ACME clients refuse
plain http.

## Pointing clients at the broker

### Certbot

```sh
certbot certonly --server https://broker.example.com/acme/directory \
  --webroot -w /tmp \
  -d www.example.com --agree-tos --no-eff-email -m ops@example.com
```

- `--server` is the only setting that matters. Certbot keeps one account per
  server URL under `/etc/letsencrypt/accounts/broker.example.com/`; renewals
  (`certbot renew`) reuse the server stored in the renewal configuration.
- Any authenticator works because no challenge is ever performed: every
  authorization the broker returns is already `valid`, and Certbot skips valid
  authorizations without calling the authenticator. `--webroot -w <any
  existing directory>` is the simplest choice (nothing is written there);
  existing renewal configurations with another plugin keep working. Do not
  combine a plugin with a `--preferred-challenges` it cannot do. No DNS plugin
  and no credentials are needed.
- `--agree-tos`: the broker publishes terms of service only when the operator
  configured them; the answer is accepted either way.
- `--no-eff-email`, `-m` / `--register-unsafely-without-email`: the contact is
  stored as metadata only (architecture §6); it is never used for anything.
- `--preferred-chain` has no effect: the broker serves exactly the chain the
  upstream CA returned and offers no alternate chains.
- `--reuse-key` keeps the same private key across renewals. It is not needed by
  the broker, but it makes the finalize step idempotent across a re-run: when a
  run is interrupted after finalize, running again with the same key produces
  the same CSR, which the broker matches to the order already in progress
  instead of rejecting.
- `--preferred-profile` is accepted and ignored (see "Profiles"); do not use
  `--required-profile`, which fails because the directory advertises no
  profiles.
- Certbot versions: any ACMEv2 Certbot that still works against Let's
  Encrypt today (POST-as-GET, `application/jose+json`) is in scope — the
  0.31 / 1.x packages of older Debian and Ubuntu releases as well as current
  2.x/3.x/4.x. Versions that only fetch resources with plain GET do not work
  (they also no longer work with Let's Encrypt).

### acme.sh

```sh
acme.sh --issue --server https://broker.example.com/acme/directory \
  -d www.example.com -w /tmp
```

- `--server` with the full directory URL. acme.sh stores it per certificate
  and uses it for `--renew` and the cron job.
- Any validation mode works for the same reason as with Certbot; webroot
  (`-w <any existing directory>`) avoids `--standalone`'s check that port 80
  is free. Nothing is written to the webroot.
- `--keylength ec-256` or RSA keys are both fine. acme.sh's account key is
  independent of the certificate key.
- `--set-default-ca --server https://broker.example.com/acme/directory` makes
  the broker the default for the host.

### Wildcards

`*.example.com` is issued only when the requesting address has an IP grant
with `wildcard=true` (architecture §4.2, `docs/authorization.md`). DNS
resolution of the name does not help. A wildcard can share an order with other
names (`-d example.com -d '*.example.com'`). The wildcard's authorization has
identifier `example.com` and `"wildcard": true`, as RFC 8555 requires.

## What the client sees at each step

| Step | Request | Broker answer |
|---|---|---|
| directory | `GET /acme/directory` | `newNonce`, `newAccount`, `newOrder`, `keyChange`, `renewalInfo`, `meta.externalAccountRequired: false`, `meta.termsOfService` when configured. No `revokeCert`, no `newAuthz`. |
| nonce | `HEAD`/`GET /acme/new-nonce` | `200` / `204` with `Replay-Nonce` and `Cache-Control: no-store`. |
| account | `POST /acme/new-account` (jwk) | `201` + `Location` for a new key; `200` + `Location` for a key that already has an account; `accountDoesNotExist` with `onlyReturnExisting` and no account. |
| order | `POST /acme/new-order` (kid) | Held while the broker waits for an admission slot (up to `scheduler.admit_wait`, default 20 s), then `201` + `Location` with status `ready`. |
| authorizations | POST-as-GET each `authorizations` URL | `valid`, one synthetic `dns-01` challenge with status `valid`. |
| finalize | `POST` the `finalize` URL with the CSR | `200` with status `valid` (certificate URL set) or `processing` plus `Retry-After`. Held up to `scheduler.finalize_wait` (default 20 s). |
| poll | POST-as-GET the order URL | Current status; `Retry-After` (`scheduler.processing_retry_after`, default 3 s) while `processing`. |
| certificate | POST-as-GET the `certificate` URL | `application/pem-certificate-chain`: leaf then intermediates, no root. |
| renewal info | `GET /acme/renewal-info/<certID>` | RFC 9773 `suggestedWindow`, optional `explanationURL`, `Retry-After`. |

Every response carries a fresh `Replay-Nonce` and
`Link: <…/acme/directory>;rel="index"`.

### Waiting at newOrder

The slow, budget-protected part of issuance happens between `newOrder` and
`finalize` (architecture §3.1, §7). `newOrder` is the only place a client
waits for capacity: the request stays open until the scheduler grants a slot,
at most `admit_wait` (20 s by default, well inside Certbot's 45 s HTTP
timeout). Once admitted the order is `ready` immediately and the broker starts
the upstream order and DNS-01 in the background while the client generates its
key and CSR. `finalize` waits up to `finalize_wait` for that preparation and
the upstream certificate; if it is not done yet the order is `processing` and
the client polls. Certbot polls for about 90 s after finalize and acme.sh up
to 30 times at the `Retry-After` interval, which covers normal DNS propagation.

An order that is not finalized within `scheduler.order_ttl` (default 15 min)
expires: polling it shows `invalid`, and finalizing it gives `orderNotReady`.
Run the client again; it creates a new order. Asking again for the same names
while an order is still open returns that same order.

## Errors and what to do

| Problem | HTTP | Meaning | What to do |
|---|---|---|---|
| `rateLimited` | 429 + `Retry-After` | A local budget protecting the upstream CA is exhausted, no slot became free in time, or the CA asked to back off. The detail names the budget. | Retry after the given time. Nothing was created upstream. |
| `serverInternal` | 503 + `Retry-After` | Every upstream CA is down. | Retry later. |
| `unauthorized` | 403 | The gate denied the request. The detail names the reason (`dns_mismatch`, `wildcard_grant_required`, `dns_failure`, `not_ipv4`, ...), the requesting address and, for a single name, a subproblem with that identifier. | Make the name resolve to the requesting host, request from the host the name points to, or ask an admin for an IP grant (wildcards always need one). `dns_failure` is transient. |
| `rejectedIdentifier` | 400 | A name is outside the managed zones or malformed; one subproblem per offending identifier. | Request names in the managed zones only. |
| `unsupportedIdentifier` | 400 | Identifier type other than `dns` (for example `ip`). | Only DNS names are issued. |
| `badCSR` | 400 | The CSR is unreadable, its names differ from the order, or the order was already finalized with a different CSR. | Use a CSR with exactly the order's names; after a key change create a new order (or use `--reuse-key`). |
| `orderNotReady` | 403 | The order expired or failed before a CSR was accepted. | Run the client again. |
| `badNonce` | 400 | Stale or reused nonce (also after a broker restart). | Clients retry automatically with the nonce from the error response. |
| `accountDoesNotExist` | 400 | The account key is unknown to this broker (for example an account created against another server). | Register again (`certbot register --server …`, or delete the stale account directory). |
| `badSignatureAlgorithm`, `badPublicKey`, `malformed` | 400 | Protocol errors: unsupported algorithm (RS256, ES256, ES384, ES512 are accepted), RSA key below 2048 bits, malformed JWS, `notBefore`/`notAfter` requested. | Client bug or very old client. |

An order whose upstream issuance failed shows status `invalid` with the CA's
problem in `error`; Certbot and acme.sh report it and stop. Create a new order
after fixing the cause.

## Renewal and ARI

- `renewalInfo` is advertised in the directory. Clients that support RFC 9773
  (current Certbot, lego, recent acme.sh) query
  `GET /acme/renewal-info/<base64url(AKI)>.<base64url(serial)>` without
  authentication. The broker answers from the upstream CA that issued the
  certificate, through the issuance engine (which caches until the CA's
  `Retry-After` and records the request as a lineage observation, see
  architecture §8). `Retry-After` is the CA's value, or 6 h when it gave none.
  A certificate the broker did not issue gives `404`.
- A client's `replaces` field in `newOrder` is passed to the engine. When it
  names a certificate the broker issued, the order echoes it back; an unknown
  `replaces` is ignored, not rejected. Clients that never send `replaces`
  (Certbot) lose nothing: the engine infers the predecessor from the same
  identifier set.
- Certificates come back unchanged from the upstream CA, so ARI identifiers
  computed by the client match what the CA knows.

## Profiles

`newOrder` may carry a `profile` (RFC draft, sent by lego `--profile` and
Certbot `--preferred-profile`). It is accepted and ignored: the upstream
profile comes from the provider configuration (`providers[].profile`). The
directory advertises no `meta.profiles`.

## Accounts

Accounts exist only so JWS requests can be verified (architecture §6). They
carry no permission; authorization is decided per request from the source
address. Supported: create, fetch (POST-as-GET, or `{}` as older Certbot
sends), contact update (`mailto:` only, at most 10), deactivation, and
`keyChange` (RFC 8555 §7.3.5; a new key already bound to another account gives
`409` with that account's `Location`). The `orders` list URL exists and is
always empty. External account binding is not required and is ignored when
sent.

## Compatibility decisions

Each choice below keeps a common client working; most mirror what Let's
Encrypt (Boulder) does, so a client that works there works here.

- **Absolute URLs from configuration**, never from the `Host` header, so the
  JWS `url` check is stable behind nginx. The `url` header must equal the
  request URL exactly, otherwise `unauthorized` (RFC 8555 §6.4).
- **Nonce on every response**, including errors and the directory, so a client
  can always retry a `badNonce` without another round trip. Nonces are
  single-use, valid for one hour, kept in memory (at most 100 000; oldest
  forgotten first) and consumed only by a correctly signed request.
- **`badNonce` detail** uses Boulder's wording ("JWS has an invalid
  anti-replay nonce"), which acme.sh matches to retry.
- **`Content-Type`** must be `application/jose+json`; parameters such as
  `charset` are tolerated. Anything else gets `415`, with one exception:
  the POST-as-GET of a certificate URL may carry
  `application/pem-certificate-chain`, because Certbot 0.31 (Debian 10's
  package) sends its `Accept` type there and otherwise fails right after
  issuance (observed in `make compat`).
- **Flattened JWS only**, one signature, no unprotected header; exactly one of
  `jwk` (newAccount, inner keyChange) and `kid` (everything else).
- **POST-as-GET** is an empty payload (`""`). For the account URL `{}` is also
  a fetch (older Certbot). Plain `GET` on resources gets `405` with a hint;
  only the directory, newNonce and renewalInfo answer `GET`.
- **Unknown request fields are ignored**, including the ACMEv1 `resource`
  field some older clients still send.
- **Field names and status values** are exactly RFC 8555's; `status` is the
  first field of order and authorization objects (acme.sh reads the first
  `"status"` it finds). Timestamps are RFC 3339 UTC with whole seconds.
- **Synthetic challenge**: authorizations carry one `dns-01` challenge with
  status `valid`, a `validated` time and a 256-bit token, because Certbot's
  parser requires a token of at least 128 bits and both clients expect a
  `challenges` array. Responding to it (`POST {}`) returns the same valid
  challenge with `Link: <authz>;rel="up"`. Authorization deactivation is
  answered (status `deactivated` in the response) but changes nothing.
- **Existing account** on newAccount is `200` with `Location` (Certbot turns
  this into "already registered"; acme.sh reads `Location`).
- **Identifiers** are returned normalized (lower case, punycode, sorted);
  clients that send normalized names (all common ones) see their own list
  back, which lego checks.
- **`Retry-After`** is always whole seconds (acme.sh sleeps that value).
- **Orders, authorizations and certificates of other accounts** answer `404`
  like unknown ones.
- **`notBefore`/`notAfter`** in newOrder are rejected with `malformed`, as
  Let's Encrypt does.
- The inner keyChange JWS should omit `nonce`; one that carries it is accepted
  and the value ignored.

The client invocations above follow from how Certbot and acme.sh treat
already-valid authorizations; the real-client runs in `test/compat`
(`make compat`: old and current Certbot, current acme.sh, against a
Pebble-backed broker) are what confirm them for each client version.

## Deliberately unsupported

- **`revokeCert`**: absent from the directory; `POST /acme/revoke-cert` gets
  `403 unauthorized`. Revocation is an operator action taken directly with the
  CA if ever needed (architecture §24).
- **http-01 / tls-alpn-01** and any real downstream validation: the broker's
  gate replaces downstream validation, and upstream validation is always
  DNS-01 through Route53.
- **ACMEv1** (`new-reg`, `new-authz`, `new-cert`): `404`.
- **`newAuthz`** (pre-authorization), alternate chains, external account
  binding, IP identifiers, `notBefore`/`notAfter`.

## Audit and metrics

The engine audits admitted orders and issuance results. The ACME server adds
what never reaches the engine (`docs/observability.md`):

- `gate` / `deny` events for gate denials and for identifiers rejected before
  the gate (`outside_managed_zone`, `invalid_identifier`), at newOrder and at
  the finalize re-check;
- `rate_limit` events when admission is refused (`rate_limited` or
  `provider_unavailable`, with the provider and the budget in the detail);
- `order` / `failed` events for finalize requests refused at the protocol
  level (bad or different CSR, order not ready).

`tlsbroker_requests_total{mode="acme"}` counts newOrder and finalize requests
by outcome; `tlsbroker_gate_decisions_total{mode="acme"}` counts every gate
decision the ACME server asked for.
