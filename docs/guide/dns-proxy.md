# DNS proxy: your own ACME account

In this mode your ACME client keeps talking to Let's Encrypt with its own
account. The broker only publishes the DNS-01 `TXT` record the CA asks for,
and removes it afterwards. Use it when a machine must keep its own CA
account; otherwise the [ACME proxy](acme-proxy.md) is simpler and protects
the CA's rate limits for everyone.

Your machine needs access, as for the other modes (see
[Getting started](getting-started.md#getting-access)). The broker's DNS
endpoint is `https://broker.example.com/dns`.

## acme.sh

acme.sh ships the hook (`dns_acmeproxy`). Leave `ACMEPROXY_USERNAME` and
`ACMEPROXY_PASSWORD` unset.

```sh
export ACMEPROXY_ENDPOINT=https://broker.example.com/dns
acme.sh --issue --dns dns_acmeproxy --dnssleep 0 -d www.example.com
```

acme.sh remembers the endpoint, so renewals need nothing more. `--dnssleep 0`
skips acme.sh's own wait: the broker answers only once the record is
publicly visible.

## certbot

Two one-line `curl` hooks:

```sh
certbot certonly --manual --preferred-challenges dns \
  --manual-auth-hook 'curl -sSf https://broker.example.com/dns/present -d "{\"fqdn\":\"_acme-challenge.$CERTBOT_DOMAIN.\",\"value\":\"$CERTBOT_VALIDATION\"}"' \
  --manual-cleanup-hook 'curl -sSf https://broker.example.com/dns/cleanup -d "{\"fqdn\":\"_acme-challenge.$CERTBOT_DOMAIN.\",\"value\":\"$CERTBOT_VALIDATION\"}"' \
  -d www.example.com
```

Keep the single quotes: certbot's hook shell fills in the variables. certbot
saves both hooks, so `certbot renew` reuses them.

## lego

lego ships the hook (`httpreq`):

```sh
HTTPREQ_ENDPOINT=https://broker.example.com/dns \
  lego --email ops@example.com --dns httpreq -d www.example.com run
```

Leave `HTTPREQ_MODE`, `HTTPREQ_USERNAME` and `HTTPREQ_PASSWORD` unset.

## Wildcards

The CA validates `example.com` and `*.example.com` through the same DNS
record, so the broker has to make sure a record it publishes for you cannot
be used by someone else to get a wildcard. The zones' **CAA records** do
that: they name the ACME accounts that may get wildcard certificates in the
zone (`issuewild` lines pinned with `accounturi`).

For you this means:

- A wildcard through the DNS proxy works only for an ACME account named in
  the zone's CAA. Ask an administrator to add your account; they need your
  account URL (below).
- Without that, get the wildcard through the [ACME proxy](acme-proxy.md)
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

## If it fails

The hook prints the broker's answer, for example `denied: dns_mismatch` or
`denied: wildcard_unprotected`. See [Troubleshooting](troubleshooting.md).
The full API is in the [API reference](api.md#dns-proxy); background in the
[DNS proxy reference](../dns-proxy.md).
