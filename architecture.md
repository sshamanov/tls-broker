# Central TLS Broker / ACME Proxy — Architecture Handoff

## 1. Purpose

Build a single centralized TLS service for heterogeneous LAN systems where:

- DNS is controlled centrally in Route53.
- Most targets are Linux/nginx, but some may be old or simple edge devices.
- Centralized TLS termination is already used where practical, but cannot be imposed on all systems.
- Internal systems should be able to obtain publicly trusted certificates with minimal or zero target-side customization.
- The service must strongly protect upstream CA rate limits.
- The service should remain simple, single-instance, and operationally transparent.

The core design provides **three issuance modes** over the same policy, Route53, scheduler, upstream CA, logging, and storage core.

Priority/order of importance:

1. **Clean ACME proxy** for unmodified ACMEv2 clients.
2. **DNS proxy** for clients that remain their own ACME client but delegate DNS-01 handling.
3. **Direct certificate API** for simple/edge devices that want a key+certificate bundle directly.

This is intentionally a **gate**, not a high-assurance PKI authorization system. DNS and LAN IP ownership are generally trusted.

---

# 2. High-Level Architecture

```text
                          LDAP
                           |
                           v
                    +--------------+
                    | Web UI / API |
                    +------+-------+
                           |
                           v
                    +--------------+
                    | Policy / Gate|
                    +------+-------+
                           |
          +----------------+----------------+
          |                |                |
          v                v                v
   Clean ACME Proxy    DNS Proxy      Direct Cert API
          |                |                |
          +----------------+----------------+
                           |
                           v
                  Admission Scheduler
                           |
                           v
                    Issuance Engine
                           |
              +------------+------------+
              |                         |
              v                         v
         Upstream CA(s)            Route53 DNS
              |
              v
      Let's Encrypt primary
      alternate CA fallback
```

Single daemon/process is preferred.

Use nginx in front only for TLS termination, connection/request limits, network path restrictions, and passing the real IPv4 source address.

---

# 3. Three Modes

## 3.1 Clean ACME Proxy — Primary Mode

Goal: allow vanilla Certbot/acme.sh-style ACMEv2 clients to point to one custom ACME directory URL without hooks or DNS credentials.

Example:

```text
certbot -> https://broker.example.com/acme/directory
```

The broker behaves as an ACMEv2 server toward the client and as an ACME client toward the upstream CA.

### Downstream authorization model

Do **not** make clients perform HTTP-01.

When a downstream ACME client creates an order, the broker evaluates the local gate.

If allowed, the downstream authorization is returned as already valid.

This is cleaner than pretending HTTP-01 was actually validated. RFC 8555 allows authorizations to already be valid based on authorization obtained outside the ACME challenge process.

### Gate logic

For every requested non-wildcard identifier:

1. Check for an explicit enabled IP/CIDR grant matching the source IPv4.
2. If found, allow according to the grant.
3. Otherwise resolve the requested DNS name:
   - Cloudflare DoH first.
   - Google DoH fallback only on resolver/transport failure.
   - No application-level DNS cache.
   - Follow CNAMEs to terminal A records.
4. If source IPv4 matches any terminal A record, allow.
5. Otherwise deny.

For multi-SAN orders without an explicit IP grant, **all** non-wildcard names must resolve to the source IP.

Wildcard identifiers always require an explicit IP grant with `wildcard=true`.

### Upstream behavior

The downstream client provides the CSR.

The broker uses the **same CSR** when finalizing the upstream order. Therefore:

- the downstream client owns its private key;
- the broker never sees the downstream private key;
- the returned certificate is the actual upstream-issued certificate.

### Admission before upstream work

Downstream clients have short patience (Certbot polls a finalized order for
roughly 90 seconds), so the slow part must not sit behind `finalize`.

- Downstream `newOrder` is the waiting point. The broker holds that request
  until the scheduler grants a slot, or answers `429` with `Retry-After`. A
  client lost here has cost nothing upstream.
- Once the slot is granted the broker creates the upstream order and runs
  DNS-01 immediately, while the client is still generating its key and CSR.
- Downstream `finalize` then only has to send the CSR upstream.

A client lost after the slot was granted but before `finalize` leaves behind an
upstream order with validated authorizations and no certificate. That consumes
no certificate rate limit; the scheduler bounds how many such orders can exist.

Authorization objects returned downstream are `valid` and carry one synthetic
`valid` `dns-01` challenge entry, because real clients expect a `challenges`
array even on a valid authorization.

---

## 3.2 DNS Proxy — Secondary/Fallback Mode

Goal: client remains the real ACME client and talks directly to its CA, but delegates DNS-01 record handling to the broker.

Use this for:

- clients with their own ACME flow;
- wildcard use where this mode is convenient;
- unusual ACME clients;
- compatibility/debug fallback if the clean ACME proxy has an interoperability issue.

This mode uses the same gate as the other modes:

- ordinary identifier: explicit IP/CIDR grant, or the name resolves to the
  source IPv4;
- wildcard identifier (`*.example.com`): explicit grant with `wildcard=true`.

### Closing the implicit wildcard

A TXT record at `_acme-challenge.N` validates `*.N` as well as `N`, and the
broker cannot see which one the client's CA order asks for. So a requester
without a wildcard grant may `present` for `N` only when public CAA policy
already prevents a foreign ACME account from obtaining `*.N`:

- look up the effective CAA RRset for `N` over DoH (climb the tree, RFC 8659);
- every `issuewild` value must be either `;` or name the issuer domain of a
  configured, enabled provider that honours RFC 8657 `accounturi`
  (`account_uri_honoured: true`), pinned with at least one `accounturi`
  parameter (spelled in lower case);
- if there is no `issuewild` property, `issue` values are judged the same way;
- otherwise deny with reason `wildcard_unprotected`.

Which account a value pins does not matter: the broker's, the operator's own
certbot hosts', or any other. Only someone who controls the zone's DNS can
publish CAA, so every pinned account is one the operator chose. The risk the
check closes is a stranger's account using a TXT record the DNS proxy
publishes for `N` to obtain `*.N`, and a CA that honours `accounturi` refuses
every account the CAA does not name. A CA that ignores `accounturi` gives no
such protection, so its values never count as pinned. The verdict needs no
configuration and no upstream account lookup.

Whether the broker itself may obtain `*.N` (ACME proxy, direct API) is a
separate question: if no pinned value names the broker's own account, the
zone is still protected for the DNS proxy, but the UI warns that the broker
cannot issue its wildcards.

Requesters with a `wildcard=true` grant skip this check. Operators are expected
to publish such CAA records at each managed zone apex; the UI shows the CAA
status of every managed zone (how many accounts are pinned at which CA, and
whether the broker's account is among them) and suggests records following
the policy of section 9: an unpinned `issue` per CA and one `issuewild` pinned
to the broker's account at Let's Encrypt, plus one `issuewild` line per ACME
account of the operator's own that needs wildcards.

Suggested API:

```text
POST /dns/present
POST /dns/cleanup
```

`present` takes:

```text
identifier (or the challenge record fqdn, _acme-challenge.<identifier>)
TXT challenge value
```

and returns a broker-generated challenge ID.

`cleanup` takes the challenge ID, or the record fqdn and value. The fqdn form
is the body stock client hooks send (acme.sh `dns_acmeproxy`, lego
`httpreq`), so those clients need no custom hook; it always means the
non-wildcard identifier, which the implicit-wildcard rule above already covers.

The broker should return success from `present` only after the exact TXT value is visible through public DNS.

Important limitation:

Because the downstream client talks directly to the CA, the broker cannot fully control upstream certificate issuance rate limits in this mode. It can only rate-limit challenge creation.

For that reason DNS proxy remains secondary.

---

## 3.3 Direct Certificate API — Edge Mode

Goal: extremely simple edge-device integration.

Single identifier only.

Examples:

```text
GET /cert/foo.example.com
GET /cert/wildcard/example.com
```

Do not place `*` directly in the path.

### Authorization

Ordinary name:

1. explicit matching IP grant -> allow;
2. otherwise automatic DNS-to-source-IP gate -> allow if it resolves to requester IPv4;
3. otherwise deny.

Wildcard:

- only explicit matching IP grant with `wildcard=true`.

### Response

```text
Content-Type: application/x-tar
```

Tar contains exactly:

```text
privkey.pem
fullchain.pem
```

No JSON requirement.

For maximum compatibility:

- RSA 2048-bit;
- traditional PKCS#1 RSA PEM:
  `-----BEGIN RSA PRIVATE KEY-----`
- unencrypted private key;
- PEM fullchain;
- Unix LF;
- no root certificate in `fullchain.pem`;
- stable filenames.

### Direct mode is a cached certificate service

The broker owns:

- private key;
- certificate;
- renewal lifecycle;
- upstream provider choice;
- local cache.

Repeated requests should normally never cause repeated upstream issuance.

A cache miss may block while initial issuance completes.

A valid cached certificate should always be served even if the upstream CA is temporarily broken.

Never serve an expired certificate.

---

# 4. Permission Model

## 4.1 User role

Each local user has one role:

```text
normal
wildcard_allowed
admin
```

Hierarchy:

```text
admin > wildcard_allowed > normal
```

And separately:

```text
blocked = true | false
```

`blocked` is a global switch.

If blocked:

- no issuance/control rights regardless of role;
- existing certificates remain untouched;
- existing IP grants remain separate capability objects;
- user may still see their own grants, the activity log (§14) and the user guide in the UI.

An `admin + blocked` state is valid and simply means blocked.

Do not create special state-transition restrictions unless implementation experience proves necessary.

## 4.2 IP grants

IP grants are **independent durable capability objects**.

Schema concept:

```text
id
owner_user_id
ip_or_cidr
enabled
wildcard
created_at
```

Important:

- grant validity is **not dynamically tied** to the owner's current role, LDAP presence, or blocked state;
- changing the owner later does not implicitly invalidate an existing grant;
- grant behavior comes from the grant itself;
- `enabled=false` disables it;
- `wildcard=true` permits wildcard issuance.

A user's role controls what grants they are allowed to create/manage:

- normal: ordinary grants for a single IPv4 address (/32);
- wildcard_allowed: ordinary or wildcard grants for a single IPv4 address;
- admin: all control-plane operations, including grants for an address range
  (an IPv4 CIDR from /8 to /32; anything wider than /8 is refused for
  everyone).

The web UI calls grants "client access" entries: a grant is an "address", a
grant wider than /32 an "address range". "Grant" stays the engineering term
(types, routes, audit type `grant_change`).

Grants are created, edited (note and `wildcard` only; the prefix and owner
never change), enabled, disabled and deleted. Users edit their own
single-address grants; admins edit any grant. Turning `wildcard` on needs
`wildcard_allowed` or admin, as creating a wildcard grant does.

Only admins create, enable or edit grants that cover more than one address. A user
who is not an admin may still disable or delete such a grant they own, but
not enable it again. Wider grants that non-admins created before this rule
stay in force (no migration); admins review them on the Client access page.

Grants are deliberately **not scoped by name**: a granted IP may request any
name in any managed zone, and in direct mode may fetch any cached identifier.
This is the relaxed trust model, not an oversight.

Do not reintroduce tokens. Machine gating is IP-based.

Certificate ownership follows from this: every certificate records the
requesting source IP and the grant that authorized its order (none when the
names resolved to the requester). Its owner is the owner of that grant. A
certificate authorized by DNS match has no owner and is shown as such, with
its source IP; it is never attributed to the owner of an unrelated grant
(§14).

## 4.3 Bootstrap administrators

Roles are local state, so something must create the first admin. Two
environment-driven mechanisms, both optional:

- `TLS_BROKER_ADMINS` — comma-separated LDAP usernames that receive the `admin`
  role whenever they log in.
- `TLS_BROKER_LOCAL_ADMIN_USER` / `TLS_BROKER_LOCAL_ADMIN_PASSWORD` — a local
  break-glass admin that authenticates without LDAP (the password may be given
  as a bcrypt hash). It works when LDAP is down or not configured yet, is always
  `admin`, and cannot be blocked from the UI.

---

# 5. LDAP and Sessions

LDAP is only the human authentication source.

LDAP does not define application roles.

Application roles and grants are local state.

## Login

At login:

1. search username under configured base/filter;
2. username must match configured LDAP filter;
3. verify password through LDAP;
4. create a local long-lived session.

LDAP configuration concept:

```yaml
ldap:
  url: ldaps://...
  bind_dn: ...
  bind_password: ...
  base_dn: ...
  user_filter: ...
```

User input must be safely escaped when inserted into LDAP filters.

## Session behavior

Keep it simple:

- LDAP is checked at login only.
- Existing sessions are not continuously revalidated against LDAP.
- Session stays valid until expiry/logout/local application decision.
- `blocked` local state takes effect immediately.

If LDAP is unavailable, existing sessions continue to work.

If LDAP config/filter is temporarily broken, existing sessions continue to work.

New logins fail until LDAP works again, except for the local break-glass admin.

Sessions are opaque random identifiers stored (hashed) in SQLite and carried in
an `HttpOnly`, `SameSite=Strict` cookie. There is no session-signing secret.
State-changing UI requests carry a per-session CSRF token.

When changing LDAP configuration through the UI/config system, test the new settings before activating the new configuration generation.

---

# 6. Downstream ACME Accounts

Downstream ACME accounts must be preserved because ACMEv2 requires stable account-key/account-URL mapping.

But they are **protocol state only**.

Store roughly:

```text
id
account_url
JWK/public key
status
created_at
optional contact metadata
```

Do not use downstream ACME accounts for:

- LDAP identity;
- wildcard rights;
- authorization;
- IP ownership;
- business permissions.

They exist to verify JWS-signed ACME requests and satisfy the protocol.

The email/contact field is metadata, not identity.

---

# 7. ACME Proxy State Machine

## 7.1 Downstream `newOrder`

Do:

1. normalize identifiers;
2. validate managed-zone membership;
3. run local gate;
4. if the same account already has an unexpired, unfinalized order for the same
   identifier set, return that order instead of creating another;
5. choose upstream provider and ask the scheduler for a slot, holding the HTTP
   request for a bounded time (default 20 s);
6. no slot or no budget: answer `429 rateLimited` (or `503` when every provider
   is down) with `Retry-After`; nothing has been created upstream;
7. slot granted: persist the downstream order with its upstream **intent**,
   return it as `ready` with already-valid authorizations, and start upstream
   preparation in the background.

Upstream preparation: create the upstream order (with `replaces` where it
applies, section 8), persist its URL, present DNS-01 through Route53, wait for
the CA to validate, clean up the TXT values.

An order that is never finalized expires after a short TTL (default 15 min):
its budget reservation is refunded and the upstream order is left to expire.

## 7.2 Downstream `finalize`

On finalize:

1. re-check the gate for the current source IP;
2. validate CSR;
3. confirm CSR identifiers match the downstream order identifiers exactly;
4. compute CSR hash and enforce idempotency;
5. wait for upstream preparation to finish, holding the request for a bounded
   time (default 20 s); if it is still running, answer `processing` with
   `Retry-After` and let the client poll the order;
6. finalize upstream with the same CSR;
7. verify returned certificate;
8. persist certificate mapping and commit the budget reservation;
9. expose certificate downstream.

Once the CSR has been sent upstream the issuance runs to completion and is
persisted whether or not the client is still there.

One downstream order maps to at most one upstream order.

Retry with the same CSR:

- reuse existing state;
- never create another upstream order.

Retry with a different CSR:

- reject;
- client must create a new order.

---

# 8. ARI and Renewal Continuity

ARI is a core requirement, not an optional optimization.

Because the clean proxy returns the real upstream certificate unchanged, downstream and upstream certificate identity can remain aligned.

Persist enough mapping to know:

```text
downstream certificate
-> upstream provider
-> upstream account
-> upstream certificate identity
-> ARI/replacement relationship
```

When the downstream client queries renewal information:

- proxy the relevant ARI information from the correct upstream provider;
- cache only as needed.

When downstream creates a replacement order using `replaces`, preserve that relationship upstream where supported.

For Let's Encrypt, ARI-qualified renewals are especially important because they are exempt from normal issuance rate limits.

## ARI rules the broker follows

Verified against Let's Encrypt (Boulder) and Google Trust Services, October 2026:

- Let's Encrypt exempts a `replaces` order from rate limits only when the
  request falls **inside the predecessor's suggested window**, comes from the
  **same upstream account**, and shares at least one identifier. Outside the
  window the order is accepted but counted normally.
- A certificate can have only one live replacement order. A second `replaces`
  is refused with `alreadyReplaced` until the first order is invalid or expired.
- Google Trust Services serves ARI but documents no quota exemption; the broker
  assumes none. Whether a provider exempts ARI renewals is a per-provider flag.

Consequences:

- Most clients never send `replaces` (Certbot only reads `renewalInfo`). When a
  downstream order has none, the broker infers it: the newest unreplaced
  certificate of the same identifier set from the same provider.
- A downstream `replaces` that does not match a certificate the broker issued
  is ignored, not rejected.
- An order is classed "ARI-qualified" only when the provider exempts ARI and
  the current time is inside the suggested window. Otherwise it is an ordinary
  renewal and uses ordinary budget.
- If the upstream answers `alreadyReplaced`, the broker retries once without
  `replaces` as an ordinary renewal.
- An upstream order that was prepared but never finalized (the client vanished)
  is **adopted** by the next downstream order for the same identifier set and
  provider instead of creating another. This keeps an abandoned order from
  blocking the replacement slot and saves order budget. An upstream order still
  serves at most one downstream order at a time.

## Provider switching during renewal

Provider switch is emergency behavior only.

Policy:

```text
new certificate:
    primary unavailable -> try next eligible provider immediately

renewal:
    primary healthy -> stay on current provider
    primary broken + plenty of certificate lifetime -> return clean temporary error
    primary broken + near expiry -> emergency switch provider
```

A provider migration becomes a fresh issuance on the fallback CA.

ARI continuity with the old CA is not preserved across provider migration.

## Emergency window

Whether a renewal is an emergency depends on how often the client comes back,
not only on the certificate. A client that checks daily can be left on a broken
primary much longer than one that checks weekly.

```text
emergency_window = fraction * certificate_lifetime
                 + safety_checks * observed_check_interval
capped at half the certificate lifetime
```

- `observed_check_interval` is tracked per certificate lineage (normalized
  identifier set) from the gaps between that lineage's requests: ARI polls,
  renewal orders, direct-mode fetches. Until two requests have been seen, a
  configured default is used.
- Defaults: `fraction = 0.05`, `safety_checks = 3`, default interval 24 h. A
  90-day certificate checked daily gets 7.5 days; checked weekly, 25.5 days.

A client that only asks for renewal when its certificate is almost gone has
chosen its own risk; the broker does not compensate for that.

---

# 9. Upstream Providers

Primary provider:

```text
Let's Encrypt
```

Use one production Let's Encrypt account.

Do not create one upstream CA account per downstream ACME account.

Reason:

- some limits are account-scoped;
- the important registered-domain and exact-identifier-set limits are not solved by per-client account sharding;
- one upstream account simplifies ARI continuity and scheduler accounting.

Support alternate ACME CAs behind a provider abstraction.

Likely future fallback:

```text
Google Trust Services
```

Potential additional fallback:

```text
ZeroSSL
```

ZeroSSL was evaluated in October 2026: ACME directory
`https://acme.zerossl.com/v2/DV90`, EAB required but reusable, free 90-day
certificates incl. wildcard, `renewalInfo` offered, CAA issuer `sectigo.com`.
Against it: a frequent-short-outage record, slow finalization, no published
quotas, and the default chain lost its legacy cross-sign in April 2026. It is
a reasonable second fallback behind Google Trust Services; the generic ACME
adapter covers it with configuration only. Not configured initially.

CAA policy for managed zones (decided October 2026):

- `issue` allows every configured provider, so ordinary names can fall back.
- `issuewild` allows **Let's Encrypt only**, pinned with `accounturi` to the
  broker's own account. Wildcards therefore never fall back to another CA, and
  the DNS-proxy wildcard protection (section 3.2) holds even for providers
  whose `accounturi` support is unconfirmed.
- The operator's own Let's Encrypt accounts (their certbot hosts) get
  `issuewild` values of their own, pinned with `accounturi`; the zone stays
  protected (section 3.2) because every value is pinned.

Revisit when every configured provider demonstrably honours `accounturi`
(mandatory for all CAs from 2027-03-15).

Do not load-balance routinely between CAs.

Preferred behavior:

```text
new issuance:
    primary while healthy/capacity-safe
    fallback if primary unavailable or locally protected

renewal:
    sticky to existing provider
    fallback only in emergency
```

Once an upstream order is created with provider A, do not silently recreate that same downstream order with provider B.

---

# 10. Rate-Limit Protection

Protecting upstream CA limits is a first-class subsystem.

Nothing that can create upstream issuance should bypass the central admission scheduler.

Flow:

```text
Clean ACME proxy ---\
Direct mode ---------> Scheduler -> Upstream CA
Scheduled renewal ---/
```

DNS proxy is the exception because the client owns the external ACME flow.

## Architectural principles

- upstream protection is more important than downstream convenience;
- conservative local 429 responses are preferable to exhausting upstream quota;
- ARI-qualified renewals get highest protection/priority;
- cache hits do not consume issuance budget;
- a downstream `newOrder` reaches upstream only after admission, and an
  abandoned one must never consume certificate budget;
- provider `Retry-After` and real rate-limit signals become authoritative local state;
- one upstream 429 should prevent repeated equivalent upstream hammering.

## Scheduler model

The scheduler is synchronous: a caller asks for admission and either gets a
ticket, waits a bounded time for one, or is refused with a retry time. There is
no persisted work queue.

It combines three things per provider:

- **Concurrency slots** — how many upstream preparations (order + DNS-01) may
  run at once. Callers wait for a slot in priority order, then first-come.
- **Rate budgets** — sliding-window counters kept below the known upstream
  limits (new orders per account, certificates per registered domain,
  certificates per exact identifier set), each with reserved headroom that only
  renewals may use. An exhausted budget refuses immediately; waiting would not
  help.
- **Provider circuit** — `Retry-After` and outage signals from the provider
  close admission for that provider until the stated time.

A ticket reserves budget at admission, commits it when a certificate is issued,
and refunds it when the order is abandoned or fails before the CSR is sent.
ARI-qualified renewals are admitted without consuming certificate budgets when
the provider exempts them.

Priority classes:

```text
1. ARI-qualified renewals
2. direct-cache certificates inside emergency window
3. clean ACME renewals inside emergency window
4. ordinary clean ACME issuance/renewal
5. direct cache misses
6. direct-cache background renewal
```

Exact numerical downstream limits should be tuned during implementation/testing.

Do not try to mathematically mirror every CA bucket perfectly.

Track enough known upstream limits and keep conservative local headroom.

Use standard ACME rate-limit errors downstream where relevant:

```text
HTTP 429
urn:ietf:params:acme:error:rateLimited
Retry-After: ...
```

Distinguish internally:

```text
RATE_LIMITED
PROVIDER_BUSY
PROVIDER_DOWN
```

---

# 11. Direct Cache Lifecycle

A direct-mode identifier maps to one cache object.

Examples:

```text
foo.example.com
*.example.com
```

The cache object owns its private key and certificate.

Normal renewal may reuse the same key.

Key rotation can be an explicit admin action later if desired.

## Behavior

```text
valid cached cert
    -> return immediately

valid cert + renewal due
    -> return current cert
    -> renew in background

valid cert + emergency window
    -> return current cert
    -> allow emergency provider failover

expired cert
    -> never serve
    -> attempt synchronous issuance/fallback
    -> 503 if impossible

no cached cert
    -> synchronous issuance attempt
```

For direct mode:

- ARI controls renewal timing when available;
- fallback timing should use a fraction of certificate lifetime if ARI is unavailable;
- renewal is **request-driven**: a fetch of an identifier whose renewal is due
  starts the background renewal. An identifier nobody fetches is never renewed,
  so vanished devices stop consuming quota. Activity is tracked per identifier,
  not per source IP.

Concurrent requests for the same identifier must collapse into one issuance job.

---

# 12. Direct Cache Storage

Do not put PEM private keys/certificates in SQLite.

Use generation directories:

```text
/var/lib/tls-broker/certs/foo.example.com/
    generations/
        000001/
            privkey.pem
            fullchain.pem
        000002/
            privkey.pem
            fullchain.pem
    current -> generations/000002
```

Renewal procedure:

1. write complete new generation;
2. verify key matches leaf certificate;
3. verify identifier;
4. verify chain parses;
5. fsync;
6. atomically switch `current`.

Filesystem generation is the truth for cert/key material.

SQLite stores metadata and active-generation references.

No special at-rest encryption is required for these direct-mode keys under the chosen trust model.

---

# 13. SQLite Scope

SQLite is justified because the service has mutable application state:

- users and local roles;
- blocked state;
- IP grants;
- sessions;
- downstream ACME accounts;
- downstream ACME orders;
- upstream order mapping;
- certificate/ARI mappings, with the source IP and authorizing grant of each certificate;
- direct-cache metadata;
- challenge state;
- provider/rate-limit state.

At expected scale, SQLite size is trivial.

Even after years, likely only a few to a few tens of MB.

Do not optimize for storage size.

Optimize for:

- transactional correctness;
- crash recovery;
- simple schema;
- idempotent order handling.

Do not store large temporary protocol bodies forever.

After completion, compact historical ACME records to useful metadata.

---

# 14. Audit Logging

Use a plain append-only structured audit log, likely JSONL rotated by size/date.

Do not build a blockchain/hash-chain/event-sourcing system.

SQLite is current authoritative state.

JSONL is readable audit history.

Audit should include:

```text
timestamp
source IP
identifier/SAN set
mode
decision
reason
provider
result
certificate expiry
LDAP username when a human control-plane action is involved
grant ID when a grant caused authorization
```

Examples of decision reason:

```text
dns_ip_match
ip_grant
wildcard_grant_required
blocked
outside_managed_zone
rate_limited
provider_unavailable
```

For DNS-gated anonymous machine issuance, do not falsely attribute the request to the owner of some unrelated IP grant.

Record the actual authorization method.

Every authenticated user sees the issuance activity:

- issuance requests and their outcome: gate decisions including denials,
  orders admitted or refused, certificates issued or failed, DNS-proxy
  publications;
- grant changes (created, enabled, disabled, deleted);
- full IP, full username, hostname/wildcard, timestamps, provider, result and
  the decision reason in words — not the free-text detail, which can carry
  resolver, upstream or internal error text.

Admin audit additionally shows the detail and the control plane:

- logins and logouts;
- role changes and blocks;
- configuration and secret changes;
- LDAP/config errors;
- provider state and failover;
- DNS cleanups and direct-cache fetches.

Visibility is decided by event type in the UI, not stored per event.

---

# 15. Configuration Versioning

Use immutable configuration generations for static/operator-managed config:

```text
<data>/config/
    000001.yaml
    000002.yaml
    000003.yaml
    current -> 000003.yaml
```

Configuration is edited by admins in the web UI (the service ships as a
container, so the UI is the primary operator surface). The UI offers the YAML
of the current generation for editing, shows validation and LDAP-test results,
activates the new generation, and can roll back to an earlier one. On first
start with no configuration the broker writes generation `000001` with defaults
and the local break-glass admin completes setup in the UI.

Secret values (Route53 credentials, LDAP bind password, EAB keys) are set
through the UI as write-only fields and stored under `<data>/secrets/`; config
generations refer to them by name and never contain them.

Update flow:

1. create new generation;
2. validate syntax;
3. validate managed zones/providers;
4. test LDAP config where applicable;
5. fsync;
6. atomically switch `current`;
7. reload/apply.

Static config includes:

- managed Route53 zones;
- upstream CA/provider definitions;
- LDAP settings;
- service/network settings;
- high-level rate-limit defaults;
- emergency threshold defaults.

Do not store users, sessions, grants, ACME accounts, orders, or direct-cache state in YAML.

Those belong in SQLite.

Four Route53 zones are expected initially.

Zone matching uses longest managed suffix.

---

# 16. DNS Gate Resolution

Hard-coded resolver behavior:

```text
Primary: Cloudflare DoH
Fallback: Google DoH
```

Not user-configurable initially.

No application-level DNS cache.

The public DoH result is the intended gate view.

No split-horizon requirement exists for this application.

Resolution behavior:

- follow CNAME chain;
- cap traversal depth;
- detect loops;
- use terminal A records only;
- IPv4 only.

If Cloudflare returns a legitimate result such as NXDOMAIN, do not query Google just to seek a different answer.

Fallback to Google only for resolver/transport/server failure.

Explicit matching IP grant should be checked **before DNS lookup**, because it is cheaper.

---

# 17. Route53 DNS-01 Engine

All upstream CA validation uses DNS-01 through Route53.

Support multiple concurrent challenges.

For a shared `_acme-challenge` name, maintain the whole active TXT RRset:

```text
_acme-challenge.foo.example.com TXT
    "value-A"
    "value-B"
    "value-C"
```

Never overwrite another active challenge value.

One serialized write queue per hosted zone.

Multiple ACME orders may run concurrently above that layer.

Cleanup removes only the challenge's own TXT value.

Challenge state can be persisted as:

```text
challenge_id
zone_id
record_name
txt_value
upstream_order_id
state
created_at
```

Possible states:

```text
pending
presenting
waiting_dns
ready
cleaning
done
failed
```

On restart, reconstruct desired active challenge state from SQLite and reconcile Route53.

Do not rely on DNS TTL for cleanup.

---

# 18. Name Normalization

Normalize every identifier before policy, cache, rate accounting, or upstream use.

Rules:

- lowercase;
- trim trailing dot;
- normalize IDNA/punycode;
- reject malformed labels;
- preserve wildcard only as leading `*.`;
- reject embedded/multiple wildcard labels;
- reject IP literals;
- reject names outside managed zones.

For multi-SAN sets:

- normalize;
- deduplicate;
- sort canonically.

This ensures stable identity for:

- rate-limit accounting;
- exact-set matching;
- cache keys;
- audit;
- ARI/replacement mapping.

---

# 19. Real Source IPv4

IPv4 only.

No IPv6 support is required.

No LAN NAT special handling is required.

If nginx fronts the broker:

- nginx captures the real TCP source IPv4;
- passes one explicit real-IP header;
- broker trusts that header only from local nginx;
- otherwise broker uses actual TCP peer IP;
- do not trust arbitrary `X-Forwarded-For` chains.

IP grants support IPv4 or IPv4 CIDR (CIDR wider than /32 for admins only,
§4.2).

---

# 20. Crash and Restart Recovery

Single-instance design.

Persist intent/state, not worker queues.

## ACME orders

The upstream intent is written **before** the upstream call and the upstream
order URL right after it, so a crash can only leave these states:

```text
intent recorded, no upstream_order_url
    -> the upstream call may or may not have happened
    -> mark INVALID, count the new-order budget as spent
    -> never create another upstream order; the client makes a new order

READY/PREPARING + upstream_order_url
    -> query upstream order after restart
    -> resume preparation (re-present DNS-01 if still pending)

PROCESSING + upstream_order_url (CSR already sent)
    -> query upstream order after restart
    -> resume
    -> never create another upstream order

VALID
    -> serve persisted result

INVALID
    -> remain failed
```

## Direct cache

On startup:

- verify active generation exists;
- inspect certificate expiry;
- rebuild renewal schedule.

If SQLite references a missing generation, use the last complete filesystem generation and repair metadata.

## Provider state

Persist hard provider `retry_after` / circuit information.

Reconstruct transient locks/queues.

## DNS

Rebuild active DNS work from nonterminal challenge rows.

---

# 21. Process and Deployment Model

Prefer one binary/service.

Modules inside one process:

- ACME frontend;
- DNS proxy API;
- direct cert API;
- LDAP/web UI;
- policy/gate;
- scheduler;
- upstream CA adapters;
- Route53 engine;
- SQLite;
- audit logging;
- Prometheus;
- Certificate Transparency inventory (read-only, §31).

Implementation language is Go. The service ships as a container image and is
deployed with Docker Compose (host networking, one data volume, settings from
an env file). It runs as an unprivileged user inside the container.

Use nginx in front.

Suggested paths:

```text
/acme/*
/dns/*
/cert/*
/ui/*
/metrics
/healthz
```

`/healthz` should reflect broker process health/readiness, not upstream CA availability.

Prometheus metrics endpoint should be restricted by nginx/network policy.

The user guide (`docs/guide.md`) is one document everywhere: a contents
list of its sections at the top, then continuous text. It ships in the
image and the UI shows it. An operator can copy it to Confluence
Server/Data Center with the manual maintenance command
`tls-broker docs publish` (root page and token from the container
environment): the whole document becomes the body of that one root page; no
child pages are created. `--prune` deletes the root's child pages left from
the earlier multi-page layout (titles starting `TLS Broker: `) and nothing
else. Confluence holds a copy; the repository is the source. The broker
process itself never talks to Confluence.

---

# 22. Secrets and Files

Everything lives under one data root (`TLS_BROKER_DATA_DIR`, `/data` in the
container, `/var/lib/tls-broker` otherwise):

```text
<data>/config/      configuration generations
<data>/secrets/     service credentials, mode 0600
<data>/state.db     SQLite
<data>/certs/       direct cert cache
<data>/audit/       audit JSONL
```

Secrets:

- Route53 credentials (optional; the standard AWS credential chain is used
  when they are not set);
- LDAP bind credentials;
- upstream CA account keys (generated by the broker);
- EAB secrets for providers that require them.

Root/service-user filesystem permissions are sufficient.

No need to split Route53, issuance, or cache into separate privileged services.

---

# 23. Backup and Restore

Back up:

1. SQLite;
2. config generations;
3. upstream CA account keys/EAB secrets;
4. direct certificate cache.

Audit history can be backed up separately.

Use SQLite-consistent backup/snapshot mechanics rather than blindly copying a live DB.

Restore:

1. config;
2. CA account secrets;
3. SQLite;
4. direct cache;
5. start service;
6. let startup reconciliation repair active orders/challenges/cache metadata.

Preserving upstream CA account keys matters for ARI/account continuity.

---

# 24. API Surface

## ACME

```text
https://broker.example.com/acme/directory
```

Implement only modern ACMEv2/RFC 8555 behavior.

Do not support ACMEv1.

Compatibility goal:

> if the client can still speak successfully to modern Let's Encrypt ACMEv2, it is in scope.

Target broad practical compatibility with:

- older ACMEv2-capable Certbot;
- Ubuntu/Debian distro Certbot packages;
- current Certbot;
- current acme.sh.

Needed ACME surface includes roughly:

```text
directory
newNonce
newAccount
account lookup/update/deactivation
keyChange (account key rollover; local protocol state only)
newOrder
authorization objects
finalize
order polling
certificate retrieval
POST-as-GET
standard ACME problems
ARI endpoint for capable clients
```

Already-valid authorization behavior should be tested carefully against older ACMEv2 clients.

`revokeCert` is not offered: it is absent from the directory and requests get
an ACME `unauthorized` problem. Certificates here are short-lived and
revocation is an operator action taken directly with the CA if ever needed.

## DNS API

```text
POST /dns/present
POST /dns/cleanup
```

Gated as described in section 3.2.

`present` returns a challenge ID and waits for DNS propagation before success.

`cleanup` is idempotent and removes only its own TXT value (the caller's,
identified by challenge ID or by record fqdn and value).

## Direct API

```text
GET /cert/foo.example.com
GET /cert/wildcard/example.com
```

Returns tar with:

```text
privkey.pem
fullchain.pem
```

Possible status semantics:

```text
200 success
403 gate/wildcard permission denied
404 invalid/outside managed zones
429 locally rate-limited
503 no valid cached cert and issuance unavailable
```

Valid cached certs should still return `200` even if upstream is currently broken.

---

# 25. Testing Requirements

Use three layers:

1. fake/mock ACME upstream;
2. Let's Encrypt staging;
3. narrow production canary.

Test clients:

- oldest practical ACMEv2-capable Certbot obtainable;
- Ubuntu/Debian historical Certbot versions;
- current Certbot;
- current acme.sh.

Critical scenarios:

- new issuance;
- renewal;
- ARI renewal;
- already-valid authz;
- same-CSR finalize retry;
- different-CSR retry rejection;
- restart during processing;
- Route53 timeout;
- DNS propagation delay;
- upstream 429;
- upstream 503/Retry-After;
- provider outage;
- emergency provider switch;
- concurrent TXT challenges;
- direct cache miss/hit/renewal;
- blocked/grant failures;
- wildcard permission;
- multi-SAN DNS gate;
- duplicate direct requests collapse to one issuance.

Important invariants:

- one downstream order -> at most one upstream order;
- one direct identifier -> one concurrent issuance job;
- valid cached direct cert survives upstream outage;
- expired direct cert is never served;
- wildcard never succeeds without explicit wildcard IP grant;
- ARI renewal stays on current provider/account when healthy.

---

# 26. Settled Simplicity Choices

Explicitly avoid:

- DB clusters;
- HA/active-active;
- microservices;
- token-based machine auth;
- per-request LDAP revalidation;
- ACMEv1 compatibility;
- blockchain/hash-chain audit designs;
- event sourcing;
- secondary NoSQL stores;
- private-key encryption for direct cache;
- application DNS caching;
- IPv6;
- NAT-aware identity logic;
- complex HTTP-01 reachability checks inside the LAN.

The service is intentionally single-instance.

Certificate renewal tolerates temporary downtime, and this is preferable to distributed coordination complexity.

---

# 27. Important Design Rationales

## Why clean ACME proxy is primary

It gives minimal target intrusion:

- standard client;
- no AWS credentials;
- no DNS plugin;
- no custom hook;
- client keeps private key;
- central service controls policy and upstream risk.

## Why downstream authorizations are already valid

Actual HTTP-01 from a central LAN broker is fragile:

- routing/VRF differences;
- firewall rules;
- port 80 conflicts;
- internal aliases;
- reachability differences.

The real gate is IP/DNS trust anyway.

Returning already-valid authorization keeps protocol semantics cleaner than pretending a challenge happened.

## Why direct mode exists

Some edge devices should be able to do little more than:

```text
curl ... | tar
```

Direct mode centralizes:

- key generation;
- cache;
- renewal;
- ARI;
- provider fallback;
- rate-limit protection.

It is intentionally the most broker-owned mode.

## Why DNS proxy remains

It is operationally cheap once the DNS engine exists and gives a useful escape hatch for custom ACME clients and wildcard workflows.

It remains secondary because upstream rate limits cannot be fully protected when the client talks directly to the CA.

## Why SQLite

The service has enough mutable state that YAML-only persistence becomes awkward:

- sessions;
- users;
- grants;
- ACME accounts;
- orders;
- mappings;
- provider state.

SQLite is simple, transactional, tiny at expected scale, and appropriate for the single-instance model.

## Why config generations still exist

Static operator configuration benefits from:

- atomic replacement;
- easy rollback;
- inspectable history.

This is separate from dynamic application state.

---

# 28. Intentionally Open for Implementation

The following should remain flexible until implementation/testing:

### ACME server library/implementation choice

Settled: Go, with a custom minimal ACMEv2 server surface on top of a JOSE
library, and an ACME client library for the upstream side. No embedded CA
server.

### Exact schema

The entities and durability boundaries are settled, but exact table/column design should follow implementation needs.

### Exact rate-limit numbers

Architecture requires:

- central scheduler;
- conservative local admission;
- ARI priority;
- provider circuits;
- renewal capacity protection.

Exact thresholds/burst sizes should be tuned with fake upstream + staging tests.

### Emergency window parameters

Formula is settled (section 8). The fraction, safety-check count and default
check interval are configurable globally.

### Alternate CA set

Let's Encrypt is primary.

Google Trust Services is a likely fallback.

ZeroSSL or others may be evaluated later.

CAA must be updated accordingly.

### Provider adapter details

Need to normalize:

```text
create/reuse account
create order
perform/finalize order
fetch certificate
ARI/replacement support
rate-limit/provider health signals
```

Do not over-generalize before implementing provider #1 and #2.

### UI details

UI can remain minimal.

Do not let UI complexity drive core architecture.

---

# 29. Recommended Implementation Order

This is not a rigid implementation plan, but a sensible risk-first sequence:

1. Implement provider/rate-limit model and fake upstream behavior first.
2. Implement Route53 DNS challenge engine.
3. Implement SQLite state and crash-safe order mapping.
4. Implement minimal clean ACME proxy state machine.
5. Add ARI passthrough/replacement continuity.
6. Validate old/current Certbot compatibility.
7. Add direct cache API.
8. Add DNS proxy API.
9. Add LDAP/UI/grant management.
10. Add alternate upstream provider and emergency failover.
11. Harden observability, audit, backup, and failure recovery.

The reason for this order is that **upstream rate-limit safety, ACME state/idempotency, and ARI continuity are the highest-risk parts**. UI and edge conveniences are comparatively straightforward.

---

# 30. Final Mental Model

The service is best understood as:

```text
              Human control plane
                    LDAP
                      |
                      v
              users / roles / IP grants
                      |
                      v
                 Local Gate
                      |
          +-----------+------------+
          |           |            |
     ACME Proxy    DNS Proxy    Direct Cache
          |           |            |
          +-----------+------------+
                      |
                Scheduler
                      |
                Issuance Core
                      |
          +-----------+-----------+
          |                       |
      Upstream CA              Route53
```

Trust model:

```text
ordinary cert:
    explicit IP grant
    OR requested DNS name resolves to source IPv4

wildcard:
    explicit IP grant with wildcard=true
```

Operational priority:

```text
protect upstream CA capacity first
preserve renewals second
keep target-side integration minimal
avoid distributed/HA complexity
```

That is the settled architecture.

---

# 31. Certificate Transparency Inventory

Added October 2026. The broker sees only the certificates it obtained
itself, but the managed zones also hold certificates from the operator's own
ACME clients and anyone else who can pass validation. Certificate
Transparency (CT) logs show all of them. The inventory reads them so the
status page shows the dynamics of issuance and renewal across the zones, and
problems, no matter who requested a certificate.

## Source and cost

- One source behind an interface (`ctlog.Source`, with a fake):
  SSLMate Cert Spotter API v1, `GET /v1/issuances?domain=<zone>`
  with `include_subdomains`, `match_wildcards` and `expand` for names,
  issuer (with its CAA domains) and the certificate (for the serial),
  unauthenticated. It merges a precertificate and its certificate into one
  issuance (same TBS hash); the inventory also keys by that hash.
- Cert Spotter returns only unexpired certificates, in discovery order, in
  pages continued with `after=<last id>` until an empty page.
- Without an account it allows 10 queries with subdomains per hour per
  client (`X-RateLimit-Limit: 10`, measured October 2026); every page,
  including the final empty one, counts. A refusal is HTTP 429 with
  `Retry-After`.
- crt.sh (the alternative) answered 502 repeatedly when tried and is known
  to be slow; it is not used.

## Cadence

- Runtime only: nothing is persisted. The first refresh starts with `Run`;
  then every `ct_inventory.interval` (default 4 h). A restart refetches
  everything.
- Zones are queried one after another with a 2 s pause between requests.
  A managed zone inside another managed zone is not queried separately.
- Each zone keeps its cursor in memory: a routine refresh asks only for
  issuances discovered since the last one, one or two requests per zone.
- The interval floor follows from the limit: at most 2 requests per zone per
  routine refresh may use at most half of the 10 per hour, so
  `interval >= zones x 24 min`, never under 1 h. The other half is left for
  the full fetch after a restart and for retries.
- A failed zone keeps its previous data; a failed request is retried once
  after 5 s (not after a 429). After a 429 the round skips the remaining
  zones. A round with failures is repeated once after 15 min (or the
  source's `Retry-After`, if longer), otherwise the next round is the
  regular one. A configuration change applies at once: a new interval moves
  the next round, a new zone is fetched immediately, `disabled` drops all
  data.
- Certificates are kept until 30 days after expiry, so a lapsed name shows as
  expired. After a restart only unexpired certificates are known again (the
  source has no history of expired ones); certificates that expire while the
  broker runs stay visible for the 30 days.

## Model

- Certificates are grouped by identifier set (sorted SAN list). The newest is
  current, the older ones are its history.
- State of the current certificate: *ok*; *renewal due* from two thirds of
  its lifetime (30 days before expiry for 90-day certificates); *overdue*
  from seven days before expiry (the last tenth for certificates shorter
  than 70 days) with no newer certificate; *expired*; *revoked*; *replaced*
  when it is past its renewal point but every name is in a newer, valid
  certificate of another set (exact names, wildcards do not cover).
- *Unexpected CA*: the issuing CA's CAA domains (from Cert Spotter, else a
  small explicit mapping of CA organisations) are not allowed by the zone's
  CAA `issue` (or, for wildcard names, `issuewild`) records. CAA is read
  through the broker's resolver at each refresh, at the zone apex or its
  closest parent with CAA, so it is today's CAA, not the one at issuance.
- Problems: overdue, expired, revoked, unexpected CA. Renewal due is shown,
  not flagged.
- "Via the broker" means the serial matches a certificate in the broker's
  store (ACME proxy or direct); otherwise "outside the broker". This is
  informational, never a problem. CT does not show which ACME account was
  used, and the inventory does not claim it.
- Recent issuance: certificates issued in the last 14 days, each a
  *renewal* (an older certificate of the same set exists), *changed names*
  (some names were in an older certificate) or *new names*.

The inventory never issues anything and never touches the scheduler or the
upstream CAs; it reads public data only.
