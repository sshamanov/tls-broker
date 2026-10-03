# Configuration

The broker is configured in three places, and the split is deliberate:

| What | Where | Changed by |
|---|---|---|
| Process settings: data directory, listen address, bootstrap administrators, log level | environment variables | the operator, restart required |
| Everything else that is static: zones, providers, LDAP, timeouts, limits | YAML generations under `<data>/config/` | an administrator in the web UI, no restart |
| Credentials: Route53 keys, LDAP bind password, EAB keys, CA account keys | files under `<data>/secrets/` | an administrator in the web UI (write-only), or the broker itself |

Users, sessions, grants, ACME accounts, orders and the direct-certificate
cache are not configuration; they live in SQLite.

Code: `internal/config`.

## Environment variables

Read once at start-up. An invalid value stops the broker with every problem
listed. Empty is the same as unset.

| Variable | Default | Meaning |
|---|---|---|
| `TLS_BROKER_DATA_DIR` | `/var/lib/tls-broker` (compose sets `/data`) | Data root; must be an absolute path. Holds `config/`, `secrets/`, `state.db`, `certs/`, `audit/`. |
| `TLS_BROKER_LISTEN` | `127.0.0.1:8080` | TCP listen address, `host:port`, port 1-65535. Keep it on loopback and put nginx in front. |
| `TLS_BROKER_ADMINS` | empty | Comma-separated LDAP usernames that receive the `admin` role at every login. Lower-cased, de-duplicated, whitespace around names ignored. |
| `TLS_BROKER_LOCAL_ADMIN_USER` | empty | Break-glass administrator that works without LDAP. Setting one of user and password without the other is an error. |
| `TLS_BROKER_LOCAL_ADMIN_PASSWORD` | empty | Plain password, or a bcrypt hash (a value starting with `$2`; it must then be a valid hash). In a compose `.env` file write every `$` of a hash as `$$`. |
| `TLS_BROKER_LOG_LEVEL` | `info` | `debug`, `info`, `warn` or `error`. |
| `TLS_BROKER_DOH_ENDPOINTS` | empty | **Development only.** Comma-separated DoH URLs (`http` or `https`) that replace the fixed Cloudflare and Google resolvers, tried in order. The DNS gate, CAA checks and DNS-01 propagation checks then see whatever these servers answer (for example `cmd/mockdoh`, see `docs/development.md`). When set, the broker logs a warning at start-up and every UI page shows a "DNS gate is mocked" banner. Never set it in production. |

## The YAML

`<data>/config/NNNNNN.yaml`. Rules that apply everywhere:

- Decoding is strict: an unknown field, a wrong type, a duplicate key or a
  second YAML document is an error. The environment-only settings above are
  not YAML fields.
- Every field is optional; an omitted field takes the default shown below. An
  empty file is the default configuration.
- Durations are strings with units: `90s`, `5m`, `1h30m`, `36h`, `7d`,
  `1d12h`, `250ms`. A bare number is rejected (except `0`).
- The file never contains secret values, only secret names (see Secrets).
- The text you save is stored verbatim, comments included.

### Reference

```yaml
server:
  # Base URL clients use, no trailing slash (one is trimmed). ACME URLs are
  # built from it. http only for testing; ACME clients need https.
  external_url: http://127.0.0.1:8080
  # Peers whose real_ip_header is believed: CIDRs or single addresses (IPv4 or
  # IPv6). Empty means no header is ever trusted. 0.0.0.0/0 is refused.
  trusted_proxies: []
  # The single header with exactly one client address. Required when
  # trusted_proxies is not empty. X-Forwarded-For is refused.
  real_ip_header: X-Real-IP
  read_timeout: 30s      # 1s..10m
  write_timeout: 5m      # 1s..1h, >= read_timeout, and longer than the longest
                         # held request: scheduler.admit_wait, finalize_wait,
                         # direct.issue_timeout, dns_proxy.present_timeout
  shutdown_grace: 25s    # 1s..10m

# Managed Route53 zones; matching uses the longest managed suffix.
zones: []
#  - name: example.com          # normalized, not a wildcard, unique
#    hosted_zone_id: Z0123456789ABCDEFGHIJ   # optional; Z + up to 31 capitals/digits.
#                                # Omitted: resolved by name through
#                                # route53:ListHostedZones at startup and on
#                                # activation (the one public hosted zone with
#                                # that name). Set it when two public zones
#                                # share the name.
#    trusted_accounts: []         # optional ACME account URLs of the operator's
#                                # own clients (absolute https, no query or
#                                # fragment, unique, at most 20). The DNS-proxy
#                                # CAA condition accepts an issuewild/issue
#                                # accounturi naming one of them for names in
#                                # this zone like the broker's own account (see
#                                # "Trusted operator accounts" below).

route53:
  region: us-east-1
  # Names of secrets. Both or neither; neither means the standard AWS
  # credential chain (environment, instance role, ...).
  access_key_id_secret: ""
  secret_access_key_secret: ""
  ttl: 60s                 # whole seconds, 1s..1d
  change_timeout: 2m       # submit until INSYNC
  propagation_timeout: 2m  # wait for public visibility
  poll_interval: 2s        # 100ms..5m, <= propagation_timeout

# In order of preference: the first enabled provider is the primary, the rest
# are fallbacks in that order. Empty is allowed (nothing can be issued yet);
# otherwise at least one must be enabled. Names are unique and are stored with
# orders: never reuse a name for a different CA.
providers: []
#  - name: letsencrypt            # [a-z0-9][a-z0-9_-]{0,63}
#    disabled: false              # defined, but unused for issuance and renewal
#    directory_url: https://...   # https only
#    contact: ops@example.com     # optional account e-mail
#    eab_key_id: ""               # external account binding: both or neither
#    eab_secret: ""               # secret holding the base64url HMAC key
#    profile: ""                  # ACME profile requested in newOrder
#    caa_issuers: [letsencrypt.org]   # required for enabled providers
#    account_uri_honoured: true   # CA enforces the RFC 8657 accounturi parameter
#    ari: true                    # serves renewal information
#    ari_exempt: true             # needs ari; replaces orders are rate-limit exempt
#    limits:                      # each omitted limit takes the default shown
#      new_orders:       {count: 200, window: 3h}
#      certs_per_domain: {count: 40,  window: 7d}
#      certs_per_set:    {count: 4,   window: 7d}   # count 0 = not enforced
#      concurrency: 4                # 1..64 parallel upstream preparations
#      renewal_reserve_percent: 25   # 0..90, share of every budget for renewals

# LDAP is off while url is empty; then every other ldap field must be empty too
# and only the local break-glass administrator can log in.
ldap:
  url: ""                  # ldaps://host:636 or ldap://host:389, nothing else
  bind_dn: ""              # with bind_password_secret, both or neither
  bind_password_secret: "" # secret name
  base_dn: ""              # required when url is set
  user_filter: ""          # required: must contain %s exactly once and parse
  starttls: false          # only with ldap://
  insecure_skip_verify: false
  timeout: 10s             # per operation, 1s..2m

sessions:
  ttl: 720h                # 5m..365d
  cookie_name: tls_broker_session
  cookie_secure: auto      # auto | always | never (true/false still read)

scheduler:
  admit_wait: 20s              # wait for a slot before "busy" (1s..5m)
  finalize_wait: 20s           # finalize holds the request this long (1s..5m)
  order_ttl: 15m               # unfinalized order lifetime (1m..24h)
  busy_retry_after: 30s
  processing_retry_after: 3s
  down_retry_after: 1m         # circuit open time, doubles up to the max;
  down_retry_after_max: 30m    # down_retry_after <= down_retry_after_max
  rate_limit_retry_after: 1h

emergency:
  fraction: 0.05               # share of the certificate lifetime, (0, 0.5]
  safety_checks: 3             # client check intervals, 1..20
  default_interval: 24h        # assumed check interval, 1h..90d

direct:
  renew_fraction: 0.6667       # share of lifetime before renewal, 0.1..0.95
  ari_poll_interval: 6h
  issue_timeout: 4m            # synchronous issuance before 503
  retry_backoff: 1m            # doubles up to the max; retry_backoff <= max
  retry_backoff_max: 1h
  rsa_bits: 2048               # 2048, 3072 or 4096

dns_proxy:
  present_timeout: 4m
  challenge_ttl: 1h            # >= present_timeout
  max_per_source: {count: 30, window: 1h}   # count 0 = not enforced

upstream:                      # shared by all providers
  http_timeout: 30s
  validation_timeout: 2m
  issue_timeout: 2m
  poll_interval: 2s
  prepare_timeout: 10m         # >= validation_timeout

resolver:
  timeout: 5s
  max_cname_hops: 8            # 1..16

audit:
  max_file_bytes: 52428800     # rotate above this, >= 1 MiB
  max_files: 0                 # rotated files kept, 0 = all
```

(The exact value written for `renew_fraction` is the float 2/3; `0.6667` above
is shortened for reading.)

### Trusted operator accounts

A requester without a wildcard grant may use the DNS proxy for `N` only when
public CAA keeps foreign ACME accounts away from `*.N` (architecture §3.2,
`docs/dns-proxy.md`). Normally that means every `issuewild` value (or `issue`
value, when there is no `issuewild`) is `;` or pinned with `accounturi` to the
broker's own account. When the operator also runs ACME clients of their own
that must keep obtaining wildcards for the zone, list their account URLs under
the zone's `trusted_accounts`:

```yaml
zones:
  - name: example.com
    trusted_accounts:
      - https://acme-v02.api.letsencrypt.org/acme/acct/111111111
      - https://acme-v02.api.letsencrypt.org/acme/acct/222222222
```

The CAA records may then contain extra `issuewild` lines such as
`0 issuewild "letsencrypt.org; accounturi=https://acme-v02.api.letsencrypt.org/acme/acct/111111111"`
and the zone still counts as protected. Exact semantics:

- The list that applies to a name is the one of the managed zone the gate
  matches it to (longest suffix); a sub-zone does not inherit its parent's
  list. The effective CAA RRset itself may sit at a parent node; only the list
  is per zone.
- A value is accepted when its issuer is an enabled provider that honours
  `accounturi` (`account_uri_honoured: true`) and every `accounturi`
  parameter is the broker's account at that provider or one of the zone's
  trusted accounts. Account URLs compare exactly (case-sensitive, no
  normalization), as the CA compares them; the parameter name must be lower
  case. A provider that does not honour `accounturi` gets no benefit from the
  list.
- Trusting an account is the operator's statement that whoever holds that
  account key may obtain wildcards in the zone. The DNS proxy still cannot be
  used by any other account: a TXT record it publishes validates `*.N` only for
  the accounts the CAA names.
- Changes take effect with the next activated generation, without a restart.
- The status page says when a verdict relied on trusted accounts, and the
  suggested CAA records for the zone are an unpinned `issue` per CA plus one
  pinned `issuewild` line per account: the broker's and each trusted one.

### Complete example

Two zones, Let's Encrypt as primary, Google Trust Services as fallback, LDAP.
The Route53 keys, the Google EAB key and the LDAP bind password must exist as
secrets before this can be activated.

<!-- example:begin -->
```yaml
server:
  external_url: https://broker.example.com
  trusted_proxies: [127.0.0.1]
  real_ip_header: X-Real-IP

zones:
  - name: example.com
    hosted_zone_id: Z0123456789ABCDEFGHIJ
    trusted_accounts:   # the operator's own certbot, which also issues *.example.com
      - https://acme-v02.api.letsencrypt.org/acme/acct/111111111
  - name: example.org
    hosted_zone_id: Z9876543210JIHGFEDCBA

route53:
  region: us-east-1
  access_key_id_secret: route53-access-key-id
  secret_access_key_secret: route53-secret-access-key

providers:
  - name: letsencrypt
    directory_url: https://acme-v02.api.letsencrypt.org/directory
    contact: ops@example.com
    caa_issuers: [letsencrypt.org]
    account_uri_honoured: true
    ari: true
    ari_exempt: true
    limits:
      new_orders: {count: 200, window: 3h}
      certs_per_domain: {count: 40, window: 7d}
      certs_per_set: {count: 4, window: 7d}
      concurrency: 4
      renewal_reserve_percent: 25
  - name: google
    directory_url: https://dv.acme-v02.api.pki.goog/directory
    contact: ops@example.com
    eab_key_id: 0123456789abcdef
    eab_secret: eab.google
    caa_issuers: [pki.goog]
    account_uri_honoured: true
    ari: true
    ari_exempt: false

ldap:
  url: ldaps://ldap.example.com:636
  bind_dn: cn=broker,ou=services,dc=example,dc=com
  bind_password_secret: ldap-bind-password
  base_dn: ou=people,dc=example,dc=com
  user_filter: (&(objectClass=person)(uid=%s))
  timeout: 10s

sessions:
  ttl: 30d

scheduler:
  admit_wait: 20s
```
<!-- example:end -->

(A test parses this block, so it cannot drift from the code.)

## Generations

`<data>/config/` holds immutable, zero-padded generation files and a symlink:

```text
000001.yaml  000002.yaml  000003.yaml  current -> 000003.yaml
```

- First start writes `000001.yaml` from the defaults; the local administrator
  then completes the setup in the UI.
- Saving in the UI (`Activate`) runs: parse (strict) → semantic validation →
  secret existence check → LDAP test when the LDAP settings differ from the
  active ones and a tester is wired → write the next number → fsync → atomically
  switch `current` → publish the new configuration and notify subscribers. If
  any step before the write fails, nothing is stored and the active generation
  stays active. The next number is always one above the highest file present.
- Writes go to a temporary file in the same directory, are fsynced, linked
  to the final name (never overwriting) and the directory is fsynced; the
  symlink is switched by renaming a new one over `current`, again fsynced.
- Rollback to generation N creates a new generation with N's content and makes
  it current; history is append-only and generation files are never edited.
  The old content is validated again (including that its secrets still exist)
  but the LDAP test is skipped.
- At start-up a missing, dangling or unusable `current` is repaired by pointing
  it at the highest generation that parses and validates (a warning is logged).
  If generation files exist but none is valid the broker refuses to start.
  A valid `current` is kept even when a higher unactivated file exists (left by
  a crash between write and switch).
- Consumers call `Current()` per operation and `Subscribe()` for change
  notifications: a channel of capacity 1, coalescing, never blocking the
  activation; after a notification call `Current()` for the final state.

## Secrets

Files in `<data>/secrets/` (directory `0700`, files `0600`, replaced
atomically). A name matches `[a-z0-9][a-z0-9._-]*`, at most 128 characters;
anything with a path separator or leading dot is rejected. Values are never
logged and never listed; the UI lists names only and sets values write-only.

The YAML refers to secrets by name; any name will do, these are the
conventional ones:

| Used by | Config field | Conventional name |
|---|---|---|
| Route53 access key ID | `route53.access_key_id_secret` | `route53-access-key-id` |
| Route53 secret access key | `route53.secret_access_key_secret` | `route53-secret-access-key` |
| LDAP bind password | `ldap.bind_password_secret` | `ldap-bind-password` |
| EAB HMAC key (base64url) of a provider | `providers[].eab_secret` | `eab.<provider>` |

The broker writes two secrets itself, per provider, and they cannot be
referenced from the YAML:

- `provider-account-key.<provider>`: the upstream account private key (PEM).
- `provider-account-url.<provider>`: the account URL once registered.

## Validation

Validation never stops at the first problem: it returns every finding, each
with a field path (`providers[1].directory_url`, `ldap.user_filter`,
`line 7` for syntax and unknown-field errors, the variable name for the
environment). Errors prevent activation; warnings do not (no zones or
providers yet, `http` external URL, `insecure_skip_verify`, a hosted zone ID
shared by two zones, ...). The ranges and relations are listed in the
reference above; in addition:

- zones: well-formed, normalized (lower case, no trailing dot), not wildcards,
  no duplicates; a hosted zone ID, when given, looks like `Z...` without
  `/hostedzone/` (an omitted one is discovered by name, see `docs/dns01.md`);
  trusted accounts are absolute `https` URLs without user info, query or
  fragment, contain no spaces, `;` or non-ASCII characters (they must fit a
  CAA parameter), are unique within the zone and at most 20; one whose host is
  no enabled provider's directory host is a warning (probably mistyped);
- providers: unique names, https directory URLs, plain e-mail contact, EAB
  fields together, CAA issuers are domain names, limit counts non-negative with
  a window whenever the count is positive;
- LDAP: scheme `ldap` or `ldaps`, `starttls` only with `ldap://`, valid DNs,
  the filter contains `%s` once and compiles with a sample user name;
- server: external URL is http(s) without query, trusted proxies are valid
  CIDRs or addresses;
- secret names must be valid and not broker-reserved, and every referenced
  secret must exist when a generation is activated.
