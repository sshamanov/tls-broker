# Troubleshooting

Every refusal carries a reason. Your client prints it (certbot and acme.sh
show the broker's error detail, `curl -S` prints the problem document), and
the web interface's **Activity** page lists every request with its outcome
and reason: search for your machine's address or the name.

## Refusal reasons

| Reason or problem | Status | What it means | What to do |
|---|---|---|---|
| `dns_mismatch` | 403 | A name does not resolve in public DNS to the address the request came from, and no client access entry covers that address. The detail says what the name resolves to. | Request from the machine the name points to, fix the DNS record, or add the machine on the Client access page. |
| `wildcard_grant_required` | 403 | A wildcard (`*.`) was requested from an address without a client access entry that allows wildcards. | Ask an administrator for the wildcard role or entry ([Getting started](getting-started.md#wildcards)). |
| `wildcard_unprotected` | 403 | DNS proxy only: the zone's CAA records do not limit who may get wildcards, so the broker will not publish the record for an ordinary entry. | Use the [ACME proxy](acme-proxy.md), or ask an administrator to add CAA records ([DNS proxy wildcards](dns-proxy.md#wildcards)). |
| `dns_failure` | 403 | Public DNS could not be asked just now. | Try again in a minute. |
| `not_ipv4` | 403 | The request came over IPv6. | Reach the broker over IPv4. |
| `outside_managed_zone`, `rejectedIdentifier` | 400 or 404 | A name is not in a zone the broker manages, or is not a valid name. | Request names in the managed zones only ([Getting started](getting-started.md#managed-zones-only)). |
| `rateLimited` | 429 | A rate limit protecting the CA is used up, or no slot became free in time. `Retry-After` says when to try again. | Wait and retry; cron and the clients' renewal timers do this by themselves. Nothing was spent at the CA. |
| `serverInternal` | 503 | No CA can issue right now (all down), or a direct download could not be issued in time. `Retry-After` is set. | Retry later. A valid certificate already in the broker is still served. |
| `badCSR` | 400 | ACME proxy: the certificate request does not match the order's names, or the order was already finalized with another key. | Run the client again; with certbot, `--reuse-key` avoids this after an interrupted run. |
| `orderNotReady` | 403 | ACME proxy: the order expired (not finished within its time limit, 15 minutes by default) or failed. | Run the client again; it creates a new order. |
| `accountDoesNotExist` | 400 | ACME proxy: the client uses an account from another server. | Register again (`certbot register --server ...`) or remove the stale account directory. |
| `badNonce` | 400 | A protocol detail, for example after a broker restart. | Clients retry by themselves. |
| DNS proxy `504` | 504 | The published record did not become visible in time. | Retry; the broker removed it again. |

## Where to look

- **Activity** (web interface): every request, allowed or denied, with the
  reason in words. Filter by mode (ACME, direct, DNS proxy) or search for the
  address.
- **Status**: whether the CAs are operational and how much rate-limit
  headroom is left.
- **Client access**: whether an entry covers your machine's address, and
  whether it is enabled and allows wildcards.
- **Certificates**: whether a certificate was issued and when it renews.

## Common questions

**My name resolves to my machine, but I get `dns_mismatch`.** The broker
asks public DNS (Cloudflare, then Google), not your local resolver. A name
that exists only in internal DNS does not count; add a client access entry
instead. Also check that the request leaves your machine from the address the
name points to (not through NAT or a proxy).

**The certificate is issued, but my service still shows the old one.** The
client got the new files; the service has not reloaded them. Add a reload
hook ([ACME proxy](acme-proxy.md#install-the-certificate-and-reload-the-service),
[direct download](direct.md#keep-it-current)).

**My blocked colleague's machines still get certificates.** Client access
entries keep working when their owner is blocked. An administrator can
disable or delete them on the Client access page.
