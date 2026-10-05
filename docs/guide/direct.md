# Direct download: curl and tar

For devices and scripts that cannot run an ACME client. Ask the broker for a
name and get the private key and certificate as a tar archive. The broker
makes the key, gets the certificate, renews it and keeps it ready.

Your machine needs access, as for the other modes (see
[Getting started](getting-started.md#getting-access)).

## Get a certificate

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

## Keep it current

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

## nginx

Point nginx at the files and run the script above from cron:

```nginx
server {
    listen 443 ssl;
    server_name www.example.com;
    ssl_certificate     /etc/ssl/broker/fullchain.pem;
    ssl_certificate_key /etc/ssl/broker/privkey.pem;
}
```

## A device or appliance

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

## When the CA is down

A valid certificate the broker already has is always served, also while
every CA is down or rate limited. Only when there is nothing valid to serve
(first request for a name, or the old one expired) does the broker answer
`503` or `429` with `Retry-After`; try again later. An expired certificate
is never served.

More: [Troubleshooting](troubleshooting.md), the
[API reference](api.md#direct-download) and the
[direct API reference](../direct-api.md).
