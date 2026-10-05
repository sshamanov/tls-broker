# TLS broker user guide

How to get publicly trusted TLS certificates for your LAN machines from the
TLS broker.

## Contents

- [Getting access](#getting-access)
- [ACME proxy (recommended)](#acme-proxy-recommended)
  - [certbot](#certbot)
  - [acme.sh](#acmesh)
  - [Reload the service](#reload-the-service)
  - [Switch an existing certificate](#switch-an-existing-certificate)
- [DNS proxy](#dns-proxy)
- [Direct download](#direct-download)
- [Web interface](#web-interface)
- [Troubleshooting](#troubleshooting)
- [API](#api)

## Getting access

The broker decides by the IPv4 address a request comes from. A request is
allowed when either holds:

- **Client access**: in the web interface, open **Client access** and add
  your machine's IPv4 address (`10.1.2.3` or `10.1.2.3/32`; several
  separated by commas or spaces).
- **The name resolves to your machine** in public DNS.

Only names in the broker's managed zones can be requested.

## ACME proxy (recommended)

Your ACME client talks to the broker instead of Let's Encrypt. Add
`--server https://broker.example.com/acme/directory`; `-w /tmp` is only
there because the clients want a validation method (nothing is written).

### certbot

```sh
certbot certonly --server https://broker.example.com/acme/directory \
  --webroot -w /tmp -d www.example.com -d api.example.com \
  --agree-tos -m ops@example.com --no-eff-email
```

Files land in `/etc/letsencrypt/live/www.example.com/`. Renewal is
automatic through the `certbot renew` timer.

### acme.sh

```sh
acme.sh --issue --server https://broker.example.com/acme/directory \
  -d www.example.com -d api.example.com -w /tmp
```

Renewal is automatic through acme.sh's cron job.

### Reload the service

```sh
certbot certonly --server https://broker.example.com/acme/directory \
  --webroot -w /tmp -d www.example.com --deploy-hook 'systemctl reload nginx'
```

```sh
acme.sh --install-cert -d www.example.com \
  --key-file /etc/nginx/tls/www.key --fullchain-file /etc/nginx/tls/www.crt \
  --reloadcmd 'systemctl reload nginx'
```

### Switch an existing certificate

```sh
certbot certonly --cert-name www.example.com --server https://broker.example.com/acme/directory --webroot -w /tmp -d www.example.com --force-renewal
```

```sh
acme.sh --issue --server https://broker.example.com/acme/directory -d www.example.com -w /tmp --force
```

Later renewals go through the broker.

## DNS proxy

Your ACME client keeps its own Let's Encrypt account; the broker only
publishes the DNS-01 record. Wildcard certificates are not available.

acme.sh:

```sh
export ACMEPROXY_ENDPOINT=https://broker.example.com/dns
acme.sh --issue --dns dns_acmeproxy --dnssleep 0 -d www.example.com
```

certbot (keep the single quotes):

```sh
certbot certonly --manual --preferred-challenges dns \
  --manual-auth-hook 'curl -sSf https://broker.example.com/dns/present -d "{\"fqdn\":\"_acme-challenge.$CERTBOT_DOMAIN.\",\"value\":\"$CERTBOT_VALIDATION\"}"' \
  --manual-cleanup-hook 'curl -sSf https://broker.example.com/dns/cleanup -d "{\"fqdn\":\"_acme-challenge.$CERTBOT_DOMAIN.\",\"value\":\"$CERTBOT_VALIDATION\"}"' \
  -d www.example.com
```

lego:

```sh
HTTPREQ_ENDPOINT=https://broker.example.com/dns lego --email ops@example.com --dns httpreq -d www.example.com run
```

Renewals reuse these settings.

## Direct download

For devices and scripts without an ACME client. The broker makes the key
and the certificate:

```sh
curl -sSf https://broker.example.com/cert/www.example.com | tar -x -C /etc/ssl/broker
```

You get `privkey.pem` (RSA private key) and `fullchain.pem` (certificate
and intermediates). Fetch regularly: renewal happens on fetch, and a name
nobody fetches is not renewed. For example, daily from cron:

```text
17 4 * * * root curl -sSf https://broker.example.com/cert/www.example.com | tar -x -C /etc/ssl/broker && systemctl reload nginx
```

## Web interface

`https://broker.example.com/ui/`, log in with your directory account.

- **Status**: whether certificates can be issued now, the queue,
  rate-limit headroom, and the certificates of the managed zones that need
  renewing soon.
- **Certificates**: every certificate in the managed zones, and those the
  broker issued, with owner, CA and validity.
- **Client access**: addresses allowed to request certificates. Add yours
  here; disable or delete your own entries.
- **Activity**: every request with its outcome and the reason for a
  refusal. Look here first when something fails.
- **Documentation**: this guide.

## Troubleshooting

| Error | What to do |
|---|---|
| `dns_mismatch` | Add your machine on Client access, or request from the machine the name resolves to (public DNS, not internal DNS). |
| `rejectedIdentifier`, `outside_managed_zone` | Request names in the managed zones only. |
| `rateLimited` (429) | Wait for `Retry-After` and run again; renewal timers retry by themselves. |
| `serverInternal` (503) | No CA can issue now. Try again later. |
| `dns_failure` | Try again in a minute. |
| `not_ipv4` | Reach the broker over IPv4. |
| `badCSR`, `orderNotReady` | Run the client again (certbot: add `--reuse-key`). |
| `accountDoesNotExist` | Register again: `certbot register --server https://broker.example.com/acme/directory`. |
| DNS proxy `504` | Try again. |
| "Only administrators can add an address range" | Add each machine's address (`10.1.2.3`). |
| Service still shows the old certificate | Add a reload ([ACME proxy](#reload-the-service), [direct download](#direct-download)). |

## API

The endpoints your machine calls, at `https://broker.example.com`. No
credentials: access is decided per request by the address.

| Method and path | Purpose |
|---|---|
| `GET /acme/directory` | ACME directory for certbot, acme.sh, lego |
| `POST /dns/present` | publish a DNS-01 value: `{"fqdn":"_acme-challenge.www.example.com.","value":"..."}` |
| `POST /dns/cleanup` | remove it again (same body) |
| `GET /dns/challenges` | list your published values |
| `DELETE /dns/challenges/{id}` | remove one value by ID |
| `GET /cert/{name}` | tar with `privkey.pem` and `fullchain.pem`; `If-None-Match` with the `ETag` gives `304` while unchanged |
