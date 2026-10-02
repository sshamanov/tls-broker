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

Do not create the upstream order at downstream `newOrder`.

Create it only when downstream calls `finalize`.

This avoids wasting upstream order capacity on abandoned downstream orders.

---

## 3.2 DNS Proxy — Secondary/Fallback Mode

Goal: client remains the real ACME client and talks directly to its CA, but delegates DNS-01 record handling to the broker.

Use this for:

- clients with their own ACME flow;
- wildcard use where this mode is convenient;
- unusual ACME clients;
- compatibility/debug fallback if the clean ACME proxy has an interoperability issue.

This mode requires an explicit IP/CIDR grant.

Do not use automatic DNS-to-source-IP authorization here.

Suggested API:

```text
POST /dns/present
POST /dns/cleanup
```

`present` takes:

```text
identifier
TXT challenge value
```

and returns a broker-generated challenge ID.

`cleanup` takes the challenge ID.

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
- user may still access public audit views depending on UI/session policy.

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

- normal: ordinary grants;
- wildcard_allowed: ordinary or wildcard grants;
- admin: all control-plane operations.

Do not reintroduce tokens. Machine gating is IP-based.

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

New logins fail until LDAP works again.

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

- normalize identifiers;
- validate managed-zone membership;
- run local gate;
- if allowed, expose authorization as already valid;
- create only a **local downstream order**.

Do **not** create the upstream order yet.

State can become:

```text
READY
```

with no upstream cost.

## 7.2 Downstream `finalize`

On finalize:

1. validate CSR;
2. confirm CSR identifiers match the downstream order identifiers exactly;
3. compute CSR hash;
4. enforce idempotency;
5. run scheduler/admission;
6. choose upstream provider;
7. create upstream ACME order;
8. perform upstream DNS-01 using Route53;
9. finalize upstream with the same CSR;
10. verify returned certificate;
11. persist certificate mapping;
12. expose certificate downstream.

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

Emergency threshold is implementation-tunable; current architectural default is roughly 10 days before expiry.

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

CAA for managed zones must allow every configured fallback provider.

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
- abandoned downstream `newOrder`s must not consume upstream orders;
- provider `Retry-After` and real rate-limit signals become authoritative local state;
- one upstream 429 should prevent repeated equivalent upstream hammering.

Suggested priority classes:

```text
1. ARI-qualified renewals
2. direct-cache certificates inside emergency window
3. clean ACME renewals inside emergency window
4. ordinary clean ACME issuance/renewal
5. direct cache misses
6. speculative/background prefetch
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
- direct cache should pre-renew certificates before devices ask for them.

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
- certificate/ARI mappings;
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

Public/authenticated audit may show:

- full IP;
- full username;
- hostname/wildcard;
- timestamps;
- provider/result.

Admin audit additionally shows:

- all grant changes;
- role changes;
- blocks;
- denied requests;
- LDAP/config errors;
- rate-limit events;
- provider failover.

---

# 15. Configuration Versioning

Use immutable configuration generations for static/operator-managed config:

```text
/etc/tls-broker/config/
    000001.yaml
    000002.yaml
    000003.yaml
    current -> 000003.yaml
```

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

IP grants support IPv4 or IPv4 CIDR.

---

# 20. Crash and Restart Recovery

Single-instance design.

Persist intent/state, not worker queues.

## ACME orders

```text
READY
    -> local only

PROCESSING + upstream_order_url
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
- Prometheus.

Run as a dedicated unprivileged user, e.g.:

```text
tls-broker
```

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

---

# 22. Secrets and Files

Service credentials:

```text
/etc/tls-broker/secrets/
```

Possible secrets:

- Route53 credentials;
- LDAP bind credentials;
- upstream CA account keys;
- EAB secrets for providers that require them;
- session-signing secret.

State:

```text
/var/lib/tls-broker/state.db
```

Direct cert cache:

```text
/var/lib/tls-broker/certs/
```

Audit:

```text
/var/log/tls-broker/audit/
```

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
account lookup/update as required
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

## DNS API

```text
POST /dns/present
POST /dns/cleanup
```

IP-grant gated.

`present` returns a challenge ID and waits for DNS propagation before success.

`cleanup` is idempotent and removes only its own TXT value.

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

Likely direction:

- custom minimal ACMEv2 server surface;
- rely on solid JOSE/JWS/ACME libraries;
- avoid embedding a full CA server unless it clearly reduces complexity.

Evaluate concrete language/library options before committing.

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

### Emergency expiry threshold

Current working default: roughly 10 days.

Keep configurable globally.

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
