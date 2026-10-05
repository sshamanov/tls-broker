# TLS broker user guide

How to get publicly trusted TLS certificates for machines on the LAN from the
TLS broker. This one document is the whole guide. The broker's web interface
shows it under **Documentation**, with the broker's real address in every
example.

## Contents

- [Getting started](#getting-started)
  - [Pick a mode](#pick-a-mode)
  - [Getting access](#getting-access)
  - [Managed zones only](#managed-zones-only)
  - [Wildcard certificates](#wildcard-certificates)
  - [Next steps](#next-steps)
- [Using the web interface](#using-the-web-interface)
  - [Status](#status)
  - [Certificates](#certificates)
  - [Client access](#client-access)
  - [Activity log](#activity-log)
  - [Roles](#roles)
- [ACME proxy: certbot and acme.sh](#acme-proxy-certbot-and-acmesh)
  - [certbot](#certbot)
  - [acme.sh](#acmesh)
  - [Renewal](#renewal)
  - [Install the certificate and reload the service](#install-the-certificate-and-reload-the-service)
  - [Switch an existing certificate to the broker](#switch-an-existing-certificate-to-the-broker)
  - [If an ACME request fails](#if-an-acme-request-fails)
- [DNS proxy: your own ACME account](#dns-proxy-your-own-acme-account)
  - [acme.sh hook](#acmesh-hook)
  - [certbot hooks](#certbot-hooks)
  - [lego hook](#lego-hook)
  - [Wildcards through the DNS proxy](#wildcards-through-the-dns-proxy)
  - [If a DNS proxy request fails](#if-a-dns-proxy-request-fails)
- [Direct download: curl and tar](#direct-download-curl-and-tar)
  - [Get a certificate](#get-a-certificate)
  - [Keep it current](#keep-it-current)
  - [nginx](#nginx)
  - [A device or appliance](#a-device-or-appliance)
  - [When the CA is down](#when-the-ca-is-down)
- [Troubleshooting](#troubleshooting)
  - [Refusal reasons](#refusal-reasons)
  - [Where to look](#where-to-look)
  - [Common questions](#common-questions)
- [API reference](#api-reference)
  - [Who may call what](#who-may-call-what)
  - [ACME proxy endpoints](#acme-proxy-endpoints)
  - [DNS proxy endpoints](#dns-proxy-endpoints)
  - [Direct download endpoints](#direct-download-endpoints)
  - [Health and metrics](#health-and-metrics)

## Getting started

The TLS broker gets publicly trusted certificates (from Let's Encrypt, with
other certificate authorities as a fallback) for machines on the LAN. It
proves domain ownership to the CA itself, through DNS records it manages, so
your machine needs no DNS credentials, no open port and no public address.

### Pick a mode

The broker offers three ways to get a certificate. All three use the same
access rules (below).

| Mode | Use it when | You run | Private key made by |
|---|---|---|---|
| [ACME proxy](#acme-proxy-certbot-and-acmesh) | the machine can run certbot or acme.sh | certbot or acme.sh with `--server https://broker.example.com/acme/directory` | your machine |
| [DNS proxy](#dns-proxy-your-own-acme-account) | the machine must keep its own ACME account with Let's Encrypt | your ACME client plus a small DNS hook that calls the broker | your machine |
| [Direct download](#direct-download-curl-and-tar) | a device or script can only run `curl` | `curl https://broker.example.com/cert/<name> \| tar -x` | the broker |

If in doubt, use the **ACME proxy**: it is an ordinary ACME client setup,
the broker spreads the load on the CA's rate limits, retries on another CA
when one is down and keeps renewals on schedule. Use **direct download** for
appliances, cameras, printers and shell scripts. Use the **DNS proxy** only
when the client has to talk to the CA itself.

### Getting access

The broker does not use passwords or tokens for certificate requests. It
looks at the IPv4 address the request comes from. A request is allowed when
either of these holds:

1. **The name points to your machine.** Every requested name resolves in
   public DNS (an `A` record, CNAMEs are followed) to the address the request
   comes from. Nothing to set up in the broker.
2. **Your machine has client access.** An entry on the
   [Client access page](#client-access) covers the address. Log in to
   the web interface, open **Client access** and add your machine's IPv4
   address (several at once, separated by commas or spaces). Users add
   single addresses; administrators can also add address ranges such as
   `10.1.2.0/24`.

Client access is not tied to names: an address with access may request any
name in the broker's managed zones. Add only machines you trust.

### Managed zones only

The broker issues certificates only for names inside the DNS zones it
manages (for example `example.com` and everything below it). Any other name
is refused (`rejectedIdentifier`). Administrators see the list of zones on
the Status page; ask one if you need another zone.

### Wildcard certificates

A wildcard certificate (`*.example.com`) is never allowed because of DNS
alone. It needs a client access entry for the requesting address with
**Allow wildcard certificates** ticked. Only users with the wildcard role and
administrators can tick that box; ask an administrator for the role or for
the entry. Through the [DNS proxy](#wildcards-through-the-dns-proxy)
wildcards have an extra condition.

### Next steps

- [Use the web interface](#using-the-web-interface) to add client access
  and to watch what happens.
- Set up your client: [ACME proxy](#acme-proxy-certbot-and-acmesh),
  [DNS proxy](#dns-proxy-your-own-acme-account) or
  [direct download](#direct-download-curl-and-tar).
- Something refused? See [Troubleshooting](#troubleshooting).

## Using the web interface

The web interface is at `https://broker.example.com/ui/`. Log in with your
directory (LDAP) account. It shows what the broker is doing and lets you
manage which machines may request certificates. The pages described below
are what every user sees; administrators get more (see [Roles](#roles)).

### Status

The start page. It shows:

- **Certificate authorities**: whether each CA is *operational*, *degraded*
  (working, but recent answers were errors or rate limits) or *unavailable*
  (with the time the broker tries again).
- **Queue**: orders in progress and requests waiting for their turn.
- **Rate-limit headroom**: how much of each CA's limits is used. *Caution*
  from 75 %, *exhausted* when nothing is left; new requests then wait or are
  refused until the window moves on.
- **Certificates in managed zones**: every certificate of the managed
  zones that the public Certificate Transparency logs show, whoever
  requested it: the broker, your own certbot or acme.sh, anyone. The ones
  that need attention come first. Each row shows the names, a state, the
  lifetime bar, the CA and whether it came **via the broker** or from
  **outside the broker** (both are fine; outside only means the broker did
  not issue it).
- **Issuance in the last 14 days**: what was issued recently in the managed
  zones, newest first: a **renewal** (newer certificate for the same names),
  **changed names** or **new names**.
- **Expiring next (broker)** and **Recent issuance (broker)**, below: the
  certificates the broker itself holds that expire soonest, and the latest
  results of requests to the broker (issued, failed, refused, denied).

The states of certificates in the managed zones:

| State | Means |
|---|---|
| ok | valid, renewal not due yet |
| renewal due | two thirds of the lifetime have passed (30 days before expiry for a 90-day certificate) and no newer certificate exists yet; clients usually renew now |
| overdue | less than seven days left and still no newer certificate: check the client that renews it |
| expired | expired in the last 30 days without a newer certificate |
| replaced | past its renewal point, but all its names are in a newer certificate with other names |
| revoked | the CA revoked it and no newer certificate exists |
| unexpected CA | issued by a CA that the zone's CAA records do not allow |

The list is read from Certificate Transparency when the broker starts and
then every few hours (4 hours by default), so a certificate issued a moment
ago appears with the next refresh. After a restart, certificates that expired
before the restart are not shown again. Certificate Transparency does not say
which ACME account obtained a certificate.

### Certificates

Two tabs. **All in managed zones** lists every set of names in the managed
zones from Certificate Transparency, with the state of its newest
certificate (see [Status](#status)) and its earlier certificates. Filter by
name, zone, state (for example *needs attention*) and whether it was
obtained via the broker or outside it.

**Issued by the broker** shows every certificate the broker obtained, in two
lists:

- **Issued to ACME clients**: certificates of ACME-proxy clients. Each row
  shows the names, the **owner**, the CA, serial, validity and whether it
  was replaced by a renewal.
- **Direct cache**: certificates the broker keeps for direct download,
  with the last fetch time and address and the next renewal.

The **owner** is the user whose client access entry allowed the request,
with that entry's address. "No owner, DNS match from" means the names
resolved to the requesting machine and no entry was needed.

The **lifetime bar** runs from issue (left) to expiry (right). The tick marks
when renewal is due, the vertical line is now. The filled part is blue while
the certificate is fine, brass once renewal is due and red when it has
expired.

Filter by name, CA, kind, and whether to include expired certificates.

### Client access

The list of addresses allowed to request certificates, with their owner.
Filter it to show everyone's entries, only yours, or one user's.

To give your machine access:

1. Find the machine's IPv4 address as the broker sees it (the address it
   uses to reach the broker, not a public NAT address).
2. Enter it under **Add address** (`10.1.2.3` or `10.1.2.3/32`), with a
   note that says what the machine is. To add several machines at once,
   separate their addresses with commas or spaces (`10.1.2.3, 10.1.2.4`, at
   most 50); the note and the wildcard choice apply to each. If any address
   is refused, nothing is added and the page says which and why. Addresses
   you already have are skipped.
3. Tick **Allow wildcard certificates** only if the machine needs `*.`
   certificates. The box appears only for users with the wildcard role and
   administrators.

You can disable, enable and delete your own entries; a disabled entry stays
in the list but allows nothing. Entries keep working when their owner leaves
or is blocked, so delete the ones you no longer need.

### Activity log

Every certificate request with its outcome: allowed or denied (and why),
orders admitted or refused, certificates issued or failed, DNS-proxy records
published, and client access changes. Search by address, name, user or
reason, and filter by type, mode and date. When a request fails, look here
first; [Troubleshooting](#troubleshooting) explains the reasons.

### Roles

| Role | Can |
|---|---|
| user | see status, certificates, client access and activity; add single-address entries and manage their own |
| user with wildcards | the same, and allow wildcards on their entries |
| administrator | everything, plus address ranges (/8 to /32) and anyone's entries, and the pages below |
| blocked | read only: own client access entries, the activity log and this documentation |

Administrators additionally see:

- on **Status**: problems that need attention (including certificates in
  the managed zones that expired, are overdue, revoked or from an unexpected
  CA, and zones whose Certificate Transparency refresh failed), CA details and all rate-limit
  budgets, the broker's CA account URLs, the managed DNS zones and whether
  their CAA records protect wildcards;
- **Users**: set roles, block and unblock accounts;
- **CAs**: the state, limits and accounts of each certificate authority;
- **Configuration**: the broker's settings, validated before they are
  activated, with history and roll back;
- **Secrets**: credentials the configuration refers to (write only);
- in the activity log: every event type with technical detail.

## ACME proxy: certbot and acme.sh

Point an ordinary ACME client at the broker instead of at Let's Encrypt. The
client keeps its own private key; the broker checks that your machine may
have the names, gets the certificate from the CA and hands it back. No DNS
plugin, no credentials, no open port.

The essence is one option:

```text
--server https://broker.example.com/acme/directory
```

plus a validation method, because both clients insist on one. Use webroot
with any existing directory (`--webroot -w /tmp` for certbot, `-w /tmp` for
acme.sh). Nothing is written there: the broker answers every validation
itself.

Your machine needs access first: its name must resolve to it, or it needs a
client access entry (see [Getting access](#getting-access)).

### certbot

One name:

```sh
certbot certonly --server https://broker.example.com/acme/directory \
  --webroot -w /tmp -d www.example.com \
  --agree-tos -m ops@example.com --no-eff-email
```

Several names in one certificate: repeat `-d`.

```sh
certbot certonly --server https://broker.example.com/acme/directory \
  --webroot -w /tmp -d www.example.com -d api.example.com
```

A wildcard needs a client access entry that allows wildcards. Quote the `*`
so the shell does not expand it:

```sh
certbot certonly --server https://broker.example.com/acme/directory \
  --webroot -w /tmp -d example.com -d '*.example.com'
```

The files land in `/etc/letsencrypt/live/<name>/` as usual.

### acme.sh

One name:

```sh
acme.sh --issue --server https://broker.example.com/acme/directory \
  -d www.example.com -w /tmp
```

Several names: repeat `-d`. A wildcard, quoted:

```sh
acme.sh --issue --server https://broker.example.com/acme/directory \
  -d example.com -d '*.example.com' -w /tmp
```

To make the broker the default for every certificate on the machine:

```sh
acme.sh --set-default-ca --server https://broker.example.com/acme/directory
```

### Renewal

Nothing special. The client stores the broker's address with the
certificate and renews through it:

- certbot: the `certbot renew` timer or cron job that the package installs.
- acme.sh: the cron job that `acme.sh --install` created.

The broker answers the clients' renewal-information requests (ARI), so
current clients renew when the CA suggests.

### Install the certificate and reload the service

certbot runs a deploy hook after every successful issue and renewal:

```sh
certbot certonly --server https://broker.example.com/acme/directory \
  --webroot -w /tmp -d www.example.com \
  --deploy-hook 'systemctl reload nginx'
```

acme.sh copies the files to their place and runs a reload command, now and
after every renewal:

```sh
acme.sh --install-cert -d www.example.com \
  --key-file /etc/nginx/tls/www.key \
  --fullchain-file /etc/nginx/tls/www.crt \
  --reloadcmd 'systemctl reload nginx'
```

### Switch an existing certificate to the broker

certbot: run `certonly` again with the same certificate name and the
broker's address. `--force-renewal` gets a new certificate now, and certbot
saves the new server and method for later renewals.

```sh
certbot certonly --cert-name www.example.com \
  --server https://broker.example.com/acme/directory \
  --webroot -w /tmp -d www.example.com --force-renewal
```

acme.sh: issue again with `--force`; acme.sh then renews through the broker.

```sh
acme.sh --issue --server https://broker.example.com/acme/directory \
  -d www.example.com -w /tmp --force
```

Existing `--install-cert` settings and deploy hooks stay as they are.

### If an ACME request fails

The client prints the broker's reason (for example `dns_mismatch` or
`rateLimited`). [Troubleshooting](#troubleshooting) says what each means,
and the web interface's **Activity** page shows every refused request.
Details of the protocol and tested client versions:
[ACME proxy reference](acme-proxy.md).

## DNS proxy: your own ACME account

In this mode your ACME client keeps talking to Let's Encrypt with its own
account. The broker only publishes the DNS-01 `TXT` record the CA asks for,
and removes it afterwards. Use it when a machine must keep its own CA
account; otherwise the [ACME proxy](#acme-proxy-certbot-and-acmesh) is simpler and protects
the CA's rate limits for everyone.

Your machine needs access, as for the other modes (see
[Getting access](#getting-access)). The broker's DNS
endpoint is `https://broker.example.com/dns`.

### acme.sh hook

acme.sh ships the hook (`dns_acmeproxy`). Leave `ACMEPROXY_USERNAME` and
`ACMEPROXY_PASSWORD` unset.

```sh
export ACMEPROXY_ENDPOINT=https://broker.example.com/dns
acme.sh --issue --dns dns_acmeproxy --dnssleep 0 -d www.example.com
```

acme.sh remembers the endpoint, so renewals need nothing more. `--dnssleep 0`
skips acme.sh's own wait: the broker answers only once the record is
publicly visible.

### certbot hooks

Two one-line `curl` hooks:

```sh
certbot certonly --manual --preferred-challenges dns \
  --manual-auth-hook 'curl -sSf https://broker.example.com/dns/present -d "{\"fqdn\":\"_acme-challenge.$CERTBOT_DOMAIN.\",\"value\":\"$CERTBOT_VALIDATION\"}"' \
  --manual-cleanup-hook 'curl -sSf https://broker.example.com/dns/cleanup -d "{\"fqdn\":\"_acme-challenge.$CERTBOT_DOMAIN.\",\"value\":\"$CERTBOT_VALIDATION\"}"' \
  -d www.example.com
```

Keep the single quotes: certbot's hook shell fills in the variables. certbot
saves both hooks, so `certbot renew` reuses them.

### lego hook

lego ships the hook (`httpreq`):

```sh
HTTPREQ_ENDPOINT=https://broker.example.com/dns \
  lego --email ops@example.com --dns httpreq -d www.example.com run
```

Leave `HTTPREQ_MODE`, `HTTPREQ_USERNAME` and `HTTPREQ_PASSWORD` unset.

### Wildcards through the DNS proxy

The CA validates `example.com` and `*.example.com` through the same DNS
record, so the broker has to make sure a record it publishes for you cannot
be used by someone else to get a wildcard. The zones' **CAA records** do
that: they name the ACME accounts that may get wildcard certificates in the
zone (`issuewild` lines pinned with `accounturi`).

For you this means:

- A wildcard through the DNS proxy works only for an ACME account named in
  the zone's CAA. Ask an administrator to add your account; they need your
  account URL (below).
- Without that, get the wildcard through the [ACME proxy](#acme-proxy-certbot-and-acmesh)
  instead. That needs no CAA change, only a client access entry that allows
  wildcards.
- In a zone without such CAA records the broker publishes records only for
  machines whose client access allows wildcards (otherwise the answer is
  `wildcard_unprotected`, also for ordinary names).

Your account URL looks like
`https://acme-v02.api.letsencrypt.org/acme/acct/123456789`:

- certbot: the `uri` field of
  `/etc/letsencrypt/accounts/acme-v02.api.letsencrypt.org/directory/*/regr.json`.
- acme.sh: `ACCOUNT_URL` in
  `~/.acme.sh/ca/acme-v02.api.letsencrypt.org/directory/ca.conf`.

### If a DNS proxy request fails

The hook prints the broker's answer, for example `denied: dns_mismatch` or
`denied: wildcard_unprotected`. See [Troubleshooting](#troubleshooting).
The full API is in the [API reference](#dns-proxy-endpoints); background in the
[DNS proxy reference](dns-proxy.md).

## Direct download: curl and tar

For devices and scripts that cannot run an ACME client. Ask the broker for a
name and get the private key and certificate as a tar archive. The broker
makes the key, gets the certificate, renews it and keeps it ready.

Your machine needs access, as for the other modes (see
[Getting access](#getting-access)).

### Get a certificate

```sh
mkdir -p /etc/ssl/broker
curl -sSf https://broker.example.com/cert/www.example.com | tar -x -C /etc/ssl/broker
```

You get two files:

| File | Content |
|---|---|
| `privkey.pem` | RSA 2048 private key, PKCS#1 (`BEGIN RSA PRIVATE KEY`), mode 0600 |
| `fullchain.pem` | the certificate followed by the intermediate certificates (no root) |

RSA and PKCS#1 work on old devices and firmware that accept nothing else.
`-f` makes `curl` fail on an error, so a refusal never overwrites good files.

A wildcard (needs a client access entry that allows wildcards) uses the
`wildcard` path, because `*` cannot go in the URL:

```sh
curl -sSf https://broker.example.com/cert/wildcard/example.com | tar -x -C /etc/ssl/broker
```

This returns the certificate for `*.example.com`.

### Keep it current

Fetch regularly, for example once a day from cron, and reload the service
only when the certificate changed. Every answer has an `ETag`; send it back
in `If-None-Match` and the broker answers `304 Not Modified` with no body
while nothing changed.

```sh
#!/bin/sh
# /usr/local/bin/broker-cert: fetch www.example.com, reload nginx on change.
set -eu
name=www.example.com
dir=/etc/ssl/broker
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
code=$(curl -sS -o "$tmp/cert.tar" -D "$tmp/headers" -w '%{http_code}' \
  -H "If-None-Match: $(cat "$dir/.etag" 2>/dev/null || true)" \
  "https://broker.example.com/cert/$name")
case $code in
200)
  tar -x -C "$dir" -f "$tmp/cert.tar"
  grep -i '^etag:' "$tmp/headers" | cut -d' ' -f2 | tr -d '\r' > "$dir/.etag"
  systemctl reload nginx
  ;;
304) ;;
*) echo "broker answered $code" >&2; exit 1 ;;
esac
```

```text
# /etc/cron.d/broker-cert
17 4 * * * root /usr/local/bin/broker-cert
```

Renewal is driven by these fetches: when a certificate is due, the next
fetch starts its renewal and a later fetch gets the new one. A name nobody
fetches is not renewed. Fetching once a day is plenty; renewal starts weeks
before expiry.

### nginx

Point nginx at the files and run the script above from cron:

```nginx
server {
    listen 443 ssl;
    server_name www.example.com;
    ssl_certificate     /etc/ssl/broker/fullchain.pem;
    ssl_certificate_key /etc/ssl/broker/privkey.pem;
}
```

### A device or appliance

Anything that can run a shell command can fetch and install the files. For
a device that takes its certificate through an upload or a command, run the
fetch on a small helper host and push the result, for example:

```sh
curl -sSf https://broker.example.com/cert/printer.example.com | tar -x -C /tmp/printer
cat /tmp/printer/privkey.pem /tmp/printer/fullchain.pem > /tmp/printer/bundle.pem
# upload /tmp/printer/bundle.pem with the device's own tool or web interface
```

The helper host then requests the name, so it needs the access (a client
access entry), not the device.

### When the CA is down

A valid certificate the broker already has is always served, also while
every CA is down or rate limited. Only when there is nothing valid to serve
(first request for a name, or the old one expired) does the broker answer
`503` or `429` with `Retry-After`; try again later. An expired certificate
is never served.

More: [Troubleshooting](#troubleshooting), the
[API reference](#direct-download-endpoints) and the
[direct API reference](direct-api.md).

## Troubleshooting

Every refusal carries a reason. Your client prints it (certbot and acme.sh
show the broker's error detail, `curl -S` prints the problem document), and
the web interface's **Activity** page lists every request with its outcome
and reason: search for your machine's address or the name.

### Refusal reasons

| Reason or problem | Status | What it means | What to do |
|---|---|---|---|
| `dns_mismatch` | 403 | A name does not resolve in public DNS to the address the request came from, and no client access entry covers that address. The detail says what the name resolves to. | Request from the machine the name points to, fix the DNS record, or add the machine on the Client access page. |
| `wildcard_grant_required` | 403 | A wildcard (`*.`) was requested from an address without a client access entry that allows wildcards. | Ask an administrator for the wildcard role or entry ([Wildcard certificates](#wildcard-certificates)). |
| `wildcard_unprotected` | 403 | DNS proxy only: the zone's CAA records do not limit who may get wildcards, so the broker will not publish the record for an ordinary entry. | Use the [ACME proxy](#acme-proxy-certbot-and-acmesh), or ask an administrator to add CAA records ([DNS proxy wildcards](#wildcards-through-the-dns-proxy)). |
| `dns_failure` | 403 | Public DNS could not be asked just now. | Try again in a minute. |
| `not_ipv4` | 403 | The request came over IPv6. | Reach the broker over IPv4. |
| `outside_managed_zone`, `rejectedIdentifier` | 400 or 404 | A name is not in a zone the broker manages, or is not a valid name. | Request names in the managed zones only ([Managed zones only](#managed-zones-only)). |
| `rateLimited` | 429 | A rate limit protecting the CA is used up, or no slot became free in time. `Retry-After` says when to try again. | Wait and retry; cron and the clients' renewal timers do this by themselves. Nothing was spent at the CA. |
| `serverInternal` | 503 | No CA can issue right now (all down), or a direct download could not be issued in time. `Retry-After` is set. | Retry later. A valid certificate already in the broker is still served. |
| `badCSR` | 400 | ACME proxy: the certificate request does not match the order's names, or the order was already finalized with another key. | Run the client again; with certbot, `--reuse-key` avoids this after an interrupted run. |
| `orderNotReady` | 403 | ACME proxy: the order expired (not finished within its time limit, 15 minutes by default) or failed. | Run the client again; it creates a new order. |
| `accountDoesNotExist` | 400 | ACME proxy: the client uses an account from another server. | Register again (`certbot register --server ...`) or remove the stale account directory. |
| `badNonce` | 400 | A protocol detail, for example after a broker restart. | Clients retry by themselves. |
| DNS proxy `504` | 504 | The published record did not become visible in time. | Retry; the broker removed it again. |

### Where to look

- **Activity** (web interface): every request, allowed or denied, with the
  reason in words. Filter by mode (ACME, direct, DNS proxy) or search for the
  address.
- **Status**: whether the CAs are operational and how much rate-limit
  headroom is left.
- **Client access**: whether an entry covers your machine's address, and
  whether it is enabled and allows wildcards.
- **Certificates**: whether a certificate was issued and when it renews.

### Common questions

**My name resolves to my machine, but I get `dns_mismatch`.** The broker
asks public DNS (Cloudflare, then Google), not your local resolver. A name
that exists only in internal DNS does not count; add a client access entry
instead. Also check that the request leaves your machine from the address the
name points to (not through NAT or a proxy).

**The certificate is issued, but my service still shows the old one.** The
client got the new files; the service has not reloaded them. Add a reload
hook ([ACME proxy](#install-the-certificate-and-reload-the-service),
[direct download](#keep-it-current)).

**Client access says "Only administrators can add an address range".**
You entered a range such as `10.1.2.0/24`. Add each machine's address
instead (`10.1.2.3` or `10.1.2.3/32`), or ask an administrator for the range.
Nobody can add a range wider than /8.

**My blocked colleague's machines still get certificates.** Client access
entries keep working when their owner is blocked. An administrator can
disable or delete them on the Client access page.

## API reference

Every public endpoint of the broker, at `https://broker.example.com`. This is
a summary; the deep references are in the repository's `docs/` directory
(linked below).

### Who may call what

Certificate requests carry **no credentials**. The broker decides from the
IPv4 address the request comes from (behind the broker's reverse proxy: the
address the proxy reports):

- an enabled client access entry covers the address (wildcards need an entry
  that allows them), or
- every requested name resolves in public DNS to that address (never enough
  for a wildcard).

Every name must be inside a managed zone. The decision is made on every
request, also for a certificate the broker already has. See
[Getting access](#getting-access).

| Endpoints | Who |
|---|---|
| `/acme/...`, `/dns/...`, `/cert/...` | any address, decided per request as above |
| `/healthz` | anyone (the operator may restrict it at the reverse proxy) |
| `/metrics` | anyone the reverse proxy lets through (normally only the monitoring host) |
| `/ui/` | the web interface; login required (`/ui/login`) |

### ACME proxy endpoints

Directory: `https://broker.example.com/acme/directory`. A standard ACME v2
server (RFC 8555) for certbot, acme.sh, lego and similar clients; how to use
it: [ACME proxy guide](#acme-proxy-certbot-and-acmesh).

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
[Troubleshooting](#troubleshooting). Deep reference:
[ACME proxy reference](acme-proxy.md).

### DNS proxy endpoints

For clients that keep their own ACME account and only need the DNS-01
`TXT` record published ([DNS proxy guide](#dns-proxy-your-own-acme-account)). JSON request
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

Deep reference: [DNS proxy reference](dns-proxy.md).

### Direct download endpoints

`GET` (or `HEAD`) only ([direct download guide](#direct-download-curl-and-tar)).

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

Deep reference: [direct API reference](direct-api.md).

### Health and metrics

| Method and path | Returns |
|---|---|
| `GET`, `HEAD /healthz` | `200 {"status":"ok"}` when the broker can take traffic, `503` with a status while starting, shutting down or when its database fails; never reflects the CAs' health |
| `GET /metrics` | Prometheus metrics: requests, issuance, rate-limit budgets, certificate expiry |

Deep reference: [observability reference](observability.md).
