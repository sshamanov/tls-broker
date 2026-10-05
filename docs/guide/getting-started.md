# Getting started

The TLS broker gets publicly trusted certificates (from Let's Encrypt, with
other certificate authorities as a fallback) for machines on the LAN. It
proves domain ownership to the CA itself, through DNS records it manages, so
your machine needs no DNS credentials, no open port and no public address.

## Pick a mode

The broker offers three ways to get a certificate. All three use the same
access rules (below).

| Mode | Use it when | You run | Private key made by |
|---|---|---|---|
| [ACME proxy](acme-proxy.md) | the machine can run certbot or acme.sh | certbot or acme.sh with `--server https://broker.example.com/acme/directory` | your machine |
| [DNS proxy](dns-proxy.md) | the machine must keep its own ACME account with Let's Encrypt | your ACME client plus a small DNS hook that calls the broker | your machine |
| [Direct download](direct.md) | a device or script can only run `curl` | `curl https://broker.example.com/cert/<name> \| tar -x` | the broker |

If in doubt, use the **ACME proxy**: it is an ordinary ACME client setup,
the broker spreads the load on the CA's rate limits, retries on another CA
when one is down and keeps renewals on schedule. Use **direct download** for
appliances, cameras, printers and shell scripts. Use the **DNS proxy** only
when the client has to talk to the CA itself.

## Getting access

The broker does not use passwords or tokens for certificate requests. It
looks at the IPv4 address the request comes from. A request is allowed when
either of these holds:

1. **The name points to your machine.** Every requested name resolves in
   public DNS (an `A` record, CNAMEs are followed) to the address the request
   comes from. Nothing to set up in the broker.
2. **Your machine has client access.** An entry on the
   [Client access page](web-ui.md#client-access) covers the address. Log in to
   the web interface, open **Client access** and add your machine's IPv4
   address. Users add single addresses; administrators can also add network
   ranges.

Client access is not tied to names: an address with access may request any
name in the broker's managed zones. Add only machines you trust.

## Managed zones only

The broker issues certificates only for names inside the DNS zones it
manages (for example `example.com` and everything below it). Any other name
is refused (`rejectedIdentifier`). Administrators see the list of zones on
the Status page; ask one if you need another zone.

## Wildcards

A wildcard certificate (`*.example.com`) is never allowed because of DNS
alone. It needs a client access entry for the requesting address with
**Allow wildcard certificates** ticked. Only users with the wildcard role and
administrators can tick that box; ask an administrator for the role or for
the entry. Through the [DNS proxy](dns-proxy.md#wildcards) wildcards have an
extra condition.

## Next steps

- [Use the web interface](web-ui.md) to add client access and to watch what
  happens.
- Set up your client: [ACME proxy](acme-proxy.md), [DNS proxy](dns-proxy.md)
  or [direct download](direct.md).
- Something refused? See [Troubleshooting](troubleshooting.md).
