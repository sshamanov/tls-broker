# Direct certificate API

The direct API is for edge devices that cannot run an ACME client: a camera,
a printer, a router, a shell script on an appliance. The device asks the
broker for a certificate by name and gets a tar with the private key and
the certificate chain. The broker owns the key, the certificate, renewal and
the choice of CA. Design background: architecture §3.3, §11, §12, §20 and
§24. Code: `internal/direct`.

## For devices

```sh
curl -sf https://broker.example.com/cert/host.example.com | tar -x -C /etc/ssl/broker
```

That leaves `/etc/ssl/broker/privkey.pem` (mode 0600) and
`/etc/ssl/broker/fullchain.pem` (mode 0644). `-f` makes curl fail on any
error status, so a failure never overwrites good files with an error
document. Run it from cron, then reload the service that uses the files.

Wildcards use a path form, because `*` must not appear in a URL path:

```sh
curl -sf https://broker.example.com/cert/wildcard/example.com | tar -x -C /etc/ssl/broker
```

returns the certificate for `*.example.com`. A path containing `*` is
answered with 404.

### Polling cheaply

Every 200 response carries an `ETag` that changes only when a new
certificate generation becomes active. Send it back in `If-None-Match` and
the broker answers `304 Not Modified` with no body while nothing changed:

```sh
etag_file=/etc/ssl/broker/.etag
code=$(curl -s -o /tmp/cert.tar -w '%{http_code}' -D /tmp/cert.hdr \
  -H "If-None-Match: $(cat "$etag_file" 2>/dev/null)" \
  https://broker.example.com/cert/host.example.com)
if [ "$code" = 200 ]; then
  tar -x -C /etc/ssl/broker -f /tmp/cert.tar
  grep -i '^etag:' /tmp/cert.hdr | cut -d' ' -f2 | tr -d '\r' > "$etag_file"
  # reload the service here
fi
```

A conditional request is still a fetch: it is authorized, audited and
counts as activity that drives renewal (see below). Polling once a day is
plenty; renewal starts weeks before expiry. `HEAD` returns the same headers
as `GET` without the body.

Responses always carry `Cache-Control: no-store`.

## Status codes

| Status | When | Body |
|---|---|---|
| 200 | A valid certificate is returned. | tar |
| 304 | `If-None-Match` matched the current generation. | none |
| 403 | The gate denied the request: the name does not resolve to the requester's IPv4 address and no IP grant covers it, a wildcard without a `wildcard=true` grant, or the source is not IPv4. | problem+json, type `unauthorized` |
| 404 | The name is invalid, outside the managed zones, or the path is malformed (`*` in the path, extra segments). | problem+json, type `rejectedIdentifier` |
| 405 | A method other than GET or HEAD. | problem+json |
| 429 | No valid certificate is cached and issuance is rate limited (broker budget, busy slots, or the CA's rate limit). | problem+json, type `rateLimited`, `Retry-After` |
| 503 | No valid certificate is cached and issuance is not possible now (CA down, issuance failed or did not finish within `direct.issue_timeout`), or DNS resolution failed during authorization. | problem+json, type `serverInternal`, `Retry-After` |

A valid cached certificate is served with 200 even while every CA is down or
rate limiting; 429 and 503 only happen when there is nothing valid to serve.
An expired certificate is never served.

Authorization is the same as for the ACME proxy (see `authorization.md`):
an explicit IP grant, or every name resolving to the requester. It is
checked on every request, also when the certificate is cached.

## File formats

| File | Format | Mode |
|---|---|---|
| `privkey.pem` | RSA 2048 (`direct.rsa_bits`), traditional PKCS#1 `-----BEGIN RSA PRIVATE KEY-----`, unencrypted, LF line endings | 0600 |
| `fullchain.pem` | PEM certificates: leaf first, then intermediates; never the root; LF line endings | 0644 |

The tar is a plain ustar archive with exactly these two regular files, in
this order, owned by uid/gid 0, with the time the generation was written as
mtime. The response is named `<name>.tar` (`_wildcard.<base>.tar` for a
wildcard) in `Content-Disposition`.

Why RSA and PKCS#1: the devices this API exists for are often old. Many
embedded TLS stacks and older OpenSSL-based firmware accept only RSA keys
and only the traditional `RSA PRIVATE KEY` encoding, not PKCS#8 or ECDSA.
The root is left out because devices already trust it and some refuse a
chain that contains it.

## Renewal lifecycle

Each identifier (`host.example.com` or `*.example.com`) is one cache object
with its own key. What a fetch does:

| Cached state | Response | Upstream work |
|---|---|---|
| valid | the certificate, at once | none |
| valid, renewal due | the current certificate, at once | one background renewal |
| valid, inside the emergency window | the current certificate, at once | one background renewal; the issuance engine may switch to a fallback CA |
| expired | never served | synchronous issuance; 429/503 if impossible |
| none | — | synchronous issuance (priority class 5); 429/503 if impossible |

- **Renewal is request-driven.** Nothing runs on a timer. A fetch of a
  certificate whose renewal is due starts the renewal; an identifier nobody
  fetches is never renewed, so a device that disappeared stops consuming CA
  quota. A device that fetches at least every few weeks always gets its
  renewed certificate well before expiry.
- **When renewal is due.** The CA's ARI suggested window decides when it is
  available: renewal is due from the window's start. Renewal information is
  fetched in the background on a fetch when it is stale (every
  `direct.ari_poll_interval`, or the CA's Retry-After) and cached in the
  entry (`RenewAt`, `NextARICheckAt`). Without ARI, renewal is due after
  `direct.renew_fraction` of the lifetime (default two thirds).
- **Emergency window.** `emergency.fraction * lifetime + emergency.safety_checks
  * observed check interval`, capped at half the lifetime (architecture §8).
  The check interval is learned per identifier from the gaps between its
  fetches. Inside the window renewal is always due; the issuance engine
  computes the same window, gives the renewal priority class 2 and may fail
  over to another CA.
- **One job per identifier.** Every issuance and renewal of an identifier
  runs as one job. Concurrent misses wait for the same issuance; a fetch
  during a running renewal does not start another one. A job that finds the
  work already done (another job just finished) does nothing.
- **Waiting.** A miss or expired fetch waits at most `direct.issue_timeout`
  (and never longer than the client stays connected). If issuance takes
  longer the client gets 503 with `Retry-After`; the job carries on, and the
  certificate is served on the next fetch.
- **Failures and backoff.** A failed attempt is recorded in the entry
  (`LastAttemptAt`, `LastError`, `Failures`). No new attempt is made for
  `direct.retry_backoff`, doubling with each consecutive failure up to
  `direct.retry_backoff_max`, or for the CA's or scheduler's Retry-After if
  that is longer. During the backoff a fetch with a valid certificate gets
  it, one without gets the last error (429 or 503) with the remaining time
  as `Retry-After`. A success resets the failure count.
- **Key reuse.** A renewal reuses the identifier's key, so a device can pin
  it or keep a CSR-less setup. A new key is generated only for the first
  issuance, after the key material was lost, or by an explicit rotation.

## Storage layout

Keys and certificates are files; SQLite holds only metadata and the active
generation number (`direct_entries`, see `data-model.md`).

```text
<data>/certs/
  host.example.com/
    generations/
      000001/privkey.pem
      000001/fullchain.pem
      000002/privkey.pem
      000002/fullchain.pem
    current -> generations/000002
  _wildcard.example.com/          # *.example.com: no "*" in paths
    ...
```

A wildcard identifier `*.<base>` is stored as `_wildcard.<base>`; a real
host name never starts with `_`, so the mapping is unambiguous.

Writing a generation: both files are written to a temporary directory and
fsynced; the material is verified (the key is PKCS#1 RSA and matches the
leaf, the leaf names the identifier, every chain certificate parses and is
signed by the next); the directory is renamed to the next number and the
parent fsynced; the `current` link is replaced atomically (a new link
renamed over it) and the identifier directory fsynced; only then is the
entry saved in SQLite. Afterwards generations beyond the newest three
(`Options.KeepGenerations`) are deleted; the active one never is.
Directories are 0700.

## Startup check and repair

Before the API serves, `Verify` checks every entry (architecture §20). The
active generation is, in this order:

1. the one `current` points at, if complete — it is newer than SQLite when
   the broker stopped between switching the link and saving the entry;
2. the one SQLite references, if complete;
3. the newest complete generation on disk.

Complete means both files present and passing the verification above.
When the choice differs from SQLite the entry is repaired: generation,
validity dates, the certificate ID and provider (looked up by the leaf's ARI
identifier), and the renewal schedule (reset, so ARI is read again on the
next fetch); `current` is pointed at it. If no complete generation is left,
the entry is reset to "no certificate" and the next fetch issues a new one
with a new key. Every repair is logged at warning level and written to the
audit log as an admin-only `error` event starting with "direct cache
repaired". Leftover temporary directories are removed and the expiry gauge
is seeded for every entry.

Directories under `<data>/certs` that have no entry at all (the entry could
not be saved after a first issuance, or a `certs` directory restored without
its database) are adopted the same way: the newest complete generation
becomes the entry, so the next fetch is a hit instead of a new issuance.
Writing a new identifier directory fsyncs `certs` itself so the directory
survives a crash together with the generation inside it.

## Rotating a key

Renewals keep the key. To replace it (suspected compromise, policy),
an administrator triggers a rotation (`Service.Rotate`; the UI exposes
it). Rotation issues a new certificate for a freshly generated key
synchronously — waiting for a job that is already running, and ignoring the
failure backoff — and makes it the active generation. It uses ordinary CA
budget. Devices pick it up on their next fetch (the `ETag` changes).

## Observability

- Metrics: `tlsbroker_direct_cache_total{result="hit"|"miss"}`,
  `tlsbroker_direct_renewals_total{result}` (background renewals),
  `tlsbroker_cert_not_after_timestamp_seconds{identifier}` per cache entry, front-end requests by outcome and gate decisions (see
  `observability.md`).
- Audit: one `direct_fetch` event per request with source IP, identifier,
  gate decision and reason, result and certificate expiry; the detail says
  `hit`, `miss` or `expired`, the generation served and whether this fetch
  started a background job (renewal, emergency renewal, renewal-information
  check); fetches that merely join a job already running say nothing.
  Served fetches are visible to every logged-in user; denials and failures
  to admins only. Issuance itself is audited by the issuance engine.
