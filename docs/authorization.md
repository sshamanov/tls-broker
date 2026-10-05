# Authorization

Who may obtain a certificate, or publish a DNS-01 challenge, for which name.
One gate (`internal/gate`) decides for all three modes; public DNS is read
through the DoH resolver (`internal/doh`). Design background:
`architecture.md` §3, §4.2, §16 and §19.

## Trust model

The broker gates **machines by source IPv4 address**, not by credentials.
A request is allowed when either:

- an **IP grant** covers the source address, or
- every requested name **resolves in public DNS to the source address**
  ("if you are where the name points, you may have its certificate").

Wildcards are never allowed by DNS: they always need a grant with
`wildcard=true`.

The source address is the TCP peer, or the configured real-IP header when the
peer is a trusted proxy (see `docs/configuration.md`). IPv6 sources are
refused (`not_ipv4`); an IPv4-mapped IPv6 address counts as its IPv4 address.

Every name must also be inside a managed zone (`outside_managed_zone`
otherwise), whatever the grant.

## Grants

A grant is an IPv4 address or CIDR with two switches, `enabled` and
`wildcard`. It is a **capability object**:

- Its effect depends only on its own fields. The gate never looks at the
  grant's owner: a grant created by a user who is later blocked, demoted or
  removed from LDAP keeps working until an admin disables or deletes it.
- It is **deliberately not scoped by name**. A granted address may request any
  name in any managed zone (and, in direct mode, fetch any cached
  identifier). Give grants only to hosts you trust with every managed zone.
- `wildcard=true` additionally permits wildcard identifiers and skips the
  DNS-proxy CAA check below.
- Every user who is not blocked sees all grants with their owner. A user
  creates grants owned by themselves and edits (note, wildcard switch),
  enables, disables or deletes only those; an admin may change any grant and
  keeps its owner. The prefix of a grant never changes: delete and add
  instead. Only `wildcard_allowed` users and
  admins may create wildcard grants or switch `wildcard` on. Only admins may create, enable or edit a
  grant for an address range: `normal` and `wildcard_allowed` users add a single
  IPv4 address (`10.1.2.3` or `10.1.2.3/32`), and may disable or delete, but
  not re-enable, a wider grant they own. Admins may add ranges from /8 to
  /32 (for example /24 or /16); a prefix wider than /8 (/0 to /7) is refused
  for everyone with 400. The server enforces all of it (someone else's grant,
  a range or re-enabling one answers 403), not just the page.
- Wider grants that users who are not admins created before that rule stay
  in force; admins review them on the Client access page (filter by owner)
  and disable or delete what should not be there.

When several enabled grants cover an address, a wildcard grant wins over an
ordinary one, then the longest prefix, then the lowest ID. That grant's ID is
the one recorded in the audit log.

Grants are checked **before** any DNS lookup: a granted host does not depend
on public DNS at all.

## DNS gate

Without a grant, every name of the request must resolve to the source:

- A records only, IPv4 only. CNAMEs are followed to the terminal A records
  (at most `resolver.max_cname_hops` hops, default 8; loops are detected).
- The source must be one of the terminal addresses. A name with several A
  records passes if any of them is the source.
- For a multi-name request, **all** names must pass. The first name that does
  not is reported in the denial.
- The view is public DNS over DoH: Cloudflare (`cloudflare-dns.com`) first,
  Google (`dns.google`) only when Cloudflare fails (transport error, timeout,
  HTTP error, malformed or truncated answer, SERVFAIL/REFUSED). A legitimate
  answer from Cloudflare, including NXDOMAIN or "no A records", is final.
  The endpoints are fixed; there is no DNS cache in the broker.
- When both resolvers fail the request is denied with `dns_failure`; the
  client may simply retry.

A DNS-gated request is never attributed to a grant, even if some unrelated
grant exists: the audit record says `dns_ip_match` with no grant ID.

## Decision table

| Request | Matching enabled grant | Result | Reason |
|---|---|---|---|
| any name outside managed zones | any | deny | `outside_managed_zone` |
| source not IPv4 | any | deny | `not_ipv4` |
| any names | `wildcard=true` | allow | `ip_grant` |
| no wildcards | ordinary | allow (dnsproxy: then CAA check) | `ip_grant` |
| with a wildcard | ordinary | deny | `wildcard_grant_required` |
| with a wildcard | none | deny | `wildcard_grant_required` |
| no wildcards, all names resolve to the source | none | allow (dnsproxy: then CAA check) | `dns_ip_match` |
| no wildcards, some name does not | none | deny | `dns_mismatch` |
| no wildcards, resolvers failed | none | deny | `dns_failure` |

The rules are identical for the ACME proxy (`acme`), the direct API
(`direct`) and the DNS proxy (`dnsproxy`); the DNS proxy adds one step.

## DNS proxy: the implicit wildcard and CAA

In DNS-proxy mode the client talks to its CA itself and only asks the broker
to publish `_acme-challenge.N`. That TXT record validates `*.N` as well as
`N`, and the broker cannot see which one the client's order is for. Without a
further check, anyone allowed to present for `N` could obtain a wildcard
certificate for `*.N` from any public CA.

So a requester **without a wildcard grant** may present for `N` only when
public CAA already stops every ACME account the operator did not choose from
obtaining `*.N`:

1. Find the effective CAA RRset for `N` (RFC 8659): ask `N`, then each
   parent up to the TLD; the first node with any CAA records wins. A CNAME at
   a node is followed for that node only; the climb continues from the
   original name's parent.
2. If the RRset has `issuewild` properties, judge those; otherwise judge the
   `issue` properties.
3. Every judged value must either forbid issuance (`;`, or an empty issuer)
   or name the CAA issuer domain of an **enabled** provider that honours RFC
   8657 `accounturi` (`account_uri_honoured: true`) and carry at least one
   `accounturi` parameter. Which account it pins does not matter — the
   broker's, your own certbot's, or any other: only someone who controls the
   zone's DNS can publish CAA, so every pinned account is one you chose, and
   a CA that honours `accounturi` refuses every other account.
4. Otherwise — no CAA anywhere, a set with neither `issue` nor `issuewild`,
   an unpinned issuer, an unknown or disabled provider, a provider that does
   not honour `accounturi`, or a malformed value — the request is denied with
   `wildcard_unprotected`.

Details that matter when writing records:

- Issuer domains are matched case-insensitively; whitespace around `;` and
  `=` is fine.
- The parameter must be spelled `accounturi` in lower case. Other spellings
  are treated as unpinned, because a CA may not recognize them.
- The verdict does not look at the account URLs and needs no configuration.
  The CA compares them byte for byte, so a mistyped URL only locks that
  account out.
- The verdict says how many accounts are pinned at which CA and whether the
  broker's own account is among them ("CAA issuewild at example.com allows
  *.example.com only to 2 pinned accounts at letsencrypt.org; the broker's
  account at letsencrypt.org is among them"). If it is not, the zone is still
  protected for the DNS proxy, but the broker itself cannot obtain `*.N`
  through the ACME proxy or the direct API; the status page warns about that
  separately.
- A failed CAA lookup denies with `dns_failure`.

Requesters with a `wildcard=true` grant skip this check; they may have the
wildcard anyway.

### Ready-to-publish CAA records

Publish at each managed zone apex (it covers every name below unless a lower
node has its own CAA records). Replace the account URLs with the broker's
own account URLs at those CAs.

Recommended (what the status page suggests): normal names from every CA, so
the broker can fall back and your own clients keep working; wildcards only
through the broker's account at Let's Encrypt (architecture §9: the most
preferred provider that honours `accounturi`; never one `issuewild` per
provider). The DNS-proxy condition only judges `issuewild`, so `issue` stays
unpinned:

```text
example.com. CAA 0 issue     "letsencrypt.org"
example.com. CAA 0 issue     "pki.goog"
example.com. CAA 0 issuewild "letsencrypt.org; accounturi=https://acme-v02.api.letsencrypt.org/acme/acct/123456789"
```

With your own ACME clients that also need wildcards: one more pinned
`issuewild` per account (the zone stays protected; nothing to configure in the
broker):

```text
example.com. CAA 0 issuewild "letsencrypt.org; accounturi=https://acme-v02.api.letsencrypt.org/acme/acct/111111111"
```

An unpinned `issuewild "letsencrypt.org"` for them instead would make the zone
unprotected.

Pinning `issue` as well (`issue "letsencrypt.org; accounturi=..."`) is
stricter for ordinary names but shuts out every account not listed there,
including your own clients.

Strictest: no wildcard certificates from any CA (wildcards then cannot be
issued for this zone at all, not even through the broker):

```text
example.com. CAA 0 issue     "letsencrypt.org; accounturi=https://acme-v02.api.letsencrypt.org/acme/acct/123456789"
example.com. CAA 0 issuewild ";"
```

Route53 record value form (one value per line, record type `CAA`):

```text
0 issue "letsencrypt.org; accounturi=https://acme-v02.api.letsencrypt.org/acme/acct/123456789"
0 issuewild ";"
```

### Trade-off with a fallback CA that does not honour `accounturi`

The judged set must not name any CA that ignores `accounturi`: for such a CA
the parameter is meaningless and any of its customers could obtain `*.N`.
Google Trust Services is configured with `accounturi` support off until it is
confirmed. Choices:

- Keep the fallback CA out of `issuewild` (as in the examples above). DNS-proxy
  presents stay possible; wildcard certificates come only from the primary.
  If the primary is down, broker wildcard issuance fails over to nothing.
- Add the fallback CA to `issuewild` (or to `issue` with no `issuewild`).
  Wildcard fallback works, but every DNS-proxy present without a wildcard
  grant is denied with `wildcard_unprotected`, because the zone is no longer
  protected. Use wildcard grants for DNS-proxy clients in that case.

If the fallback CA is missing from `issue`, the broker cannot fail over to it
for that zone at all. The UI's CAA panel shows, per managed zone, the
effective node and records, whether wildcards are protected (and why not),
whether the broker's own account is among the pinned ones, and which enabled
providers the records do not permit.

## Decision reasons

| Reason | Allowed | Meaning |
|---|---|---|
| `ip_grant` | yes | An enabled grant covers the source; the grant ID is recorded. |
| `dns_ip_match` | yes | Every name resolves to the source; no grant is recorded. |
| `outside_managed_zone` | no | A name is not in any managed zone. |
| `not_ipv4` | no | The source address is not IPv4. |
| `invalid_identifier` | no | The request had no usable identifiers. |
| `wildcard_grant_required` | no | A wildcard was requested without a `wildcard=true` grant. |
| `dns_mismatch` | no | A name does not resolve to the source (or has no A records). |
| `dns_failure` | no | Both DoH resolvers failed (retryable), or the CNAME chain looped or was too long. |
| `wildcard_unprotected` | no | DNS proxy: CAA does not keep foreign accounts away from `*.N`. |

Denials carry the offending name and an operator-readable detail (resolved
addresses, the CAA value that failed). `blocked`, `rate_limited` and
`provider_unavailable` are decided elsewhere (control plane, scheduler) and
use the same vocabulary in the audit log.
