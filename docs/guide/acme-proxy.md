# ACME proxy: certbot and acme.sh

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
client access entry (see [Getting started](getting-started.md#getting-access)).

## certbot

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

## acme.sh

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

## Renewal

Nothing special. The client stores the broker's address with the
certificate and renews through it:

- certbot: the `certbot renew` timer or cron job that the package installs.
- acme.sh: the cron job that `acme.sh --install` created.

The broker answers the clients' renewal-information requests (ARI), so
current clients renew when the CA suggests.

## Install the certificate and reload the service

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

## Switch an existing certificate to the broker

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

## If it fails

The client prints the broker's reason (for example `dns_mismatch` or
`rateLimited`). [Troubleshooting](troubleshooting.md) says what each means,
and the web interface's **Activity** page shows every refused request.
Details of the protocol and tested client versions:
[ACME proxy reference](../acme-proxy.md).
