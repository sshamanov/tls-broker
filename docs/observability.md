# Observability

Three things tell an operator what the broker is doing: the audit log (what
was decided and why), Prometheus metrics (how much, how fast, how close to the
limits) and `/healthz` (is the process fit to take traffic). Code:
`internal/audit`, `internal/metrics`, `internal/httpx`.

## Audit log

Append-only JSONL under `<data>/audit/`: one JSON object per line, no hash
chain. SQLite is the authoritative state; the log is readable history. Unused
fields are omitted.

| Field | Meaning |
|---|---|
| `time` | RFC 3339 UTC, set by the broker when the event is recorded |
| `type` | `gate`, `order`, `issue`, `direct_fetch`, `dns_present`, `dns_cleanup`, `login`, `logout`, `grant_change`, `user_change`, `config_change`, `rate_limit`, `provider_state`, `provider_failover`, `error` |
| `visibility` | `public` (every logged-in user) or absent (admins only) |
| `mode` | `acme`, `direct`, `dnsproxy` or `ui` |
| `source_ip` | real source IPv4 of the request |
| `names` | normalized identifier set |
| `decision`, `reason` | `allow`/`deny` and the gate reason (`dns_ip_match`, `ip_grant`, `wildcard_grant_required`, `dns_mismatch`, `outside_managed_zone`, `blocked`, `rate_limited`, `provider_unavailable`, ...). The reason records the actual authorization method |
| `provider` | upstream CA involved |
| `result` | `ok`, `denied` or `failed` |
| `cert_not_after` | expiry of the certificate issued or served |
| `username` | LDAP user, only for human control-plane actions |
| `grant_id` | only when that grant caused the authorization |
| `order_id`, `certificate_id` | correlation ids |
| `detail` | free text for operators, never secrets |

Example line per event type (wrapped here for reading; in the file each is one
line):

```json
{"time":"2026-10-02T09:15:01Z","type":"gate","visibility":"public","mode":"acme","source_ip":"10.1.2.3","names":["web.example.com"],"decision":"allow","reason":"dns_ip_match"}
{"time":"2026-10-02T09:15:02Z","type":"order","visibility":"public","mode":"acme","source_ip":"10.1.2.3","names":["web.example.com"],"decision":"allow","reason":"dns_ip_match","provider":"letsencrypt","order_id":"o_8f2c"}
{"time":"2026-10-02T09:15:41Z","type":"issue","visibility":"public","mode":"acme","source_ip":"10.1.2.3","names":["web.example.com"],"provider":"letsencrypt","result":"ok","cert_not_after":"2027-01-01T09:15:40Z","order_id":"o_8f2c","certificate_id":"c_19ab"}
{"time":"2026-10-02T09:20:00Z","type":"direct_fetch","visibility":"public","mode":"direct","source_ip":"10.1.2.4","names":["db.example.com"],"decision":"allow","reason":"ip_grant","grant_id":7,"result":"ok","cert_not_after":"2026-12-20T00:00:00Z"}
{"time":"2026-10-02T09:21:10Z","type":"dns_present","visibility":"public","mode":"dnsproxy","source_ip":"10.1.2.5","names":["_acme-challenge.app.example.com"],"decision":"allow","reason":"dns_ip_match","result":"ok"}
{"time":"2026-10-02T09:22:30Z","type":"dns_cleanup","visibility":"public","mode":"dnsproxy","source_ip":"10.1.2.5","names":["_acme-challenge.app.example.com"],"result":"ok"}
{"time":"2026-10-02T09:30:00Z","type":"login","visibility":"public","mode":"ui","source_ip":"10.1.2.9","username":"alice","result":"ok"}
{"time":"2026-10-02T09:45:00Z","type":"logout","visibility":"public","mode":"ui","source_ip":"10.1.2.9","username":"alice"}
{"time":"2026-10-02T10:00:00Z","type":"grant_change","mode":"ui","source_ip":"10.1.2.9","username":"alice","grant_id":8,"detail":"created grant 10.1.2.0/24 wildcard=false"}
{"time":"2026-10-02T10:01:00Z","type":"user_change","mode":"ui","source_ip":"10.1.2.9","username":"alice","detail":"bob: blocked=true"}
{"time":"2026-10-02T10:05:00Z","type":"config_change","mode":"ui","username":"alice","detail":"activated generation 12"}
{"time":"2026-10-02T10:10:00Z","type":"gate","mode":"acme","source_ip":"10.9.9.9","names":["*.example.com"],"decision":"deny","reason":"wildcard_grant_required","result":"denied"}
{"time":"2026-10-02T10:11:00Z","type":"rate_limit","mode":"acme","source_ip":"10.1.2.3","names":["web.example.com"],"provider":"letsencrypt","reason":"rate_limited","result":"denied","detail":"cert_domain budget example.com exhausted"}
{"time":"2026-10-02T10:12:00Z","type":"provider_state","provider":"letsencrypt","detail":"circuit opened (rate_limited) until 2026-10-02T11:12:00Z"}
{"time":"2026-10-02T10:13:00Z","type":"provider_failover","mode":"acme","names":["web.example.com"],"provider":"gts","detail":"emergency switch from letsencrypt"}
{"time":"2026-10-02T10:14:00Z","type":"error","detail":"LDAP unreachable: dial timeout"}
```

### Files, rotation, retention

- Files are named `audit-YYYY-MM-DD.jsonl` (UTC day of the write). When a file
  reaches `audit.max_file_bytes` (default 50 MiB) the next event goes to
  `audit-YYYY-MM-DD.1.jsonl`, then `.2`, and so on; a file can exceed the
  limit by one line. A new day always starts a new file. After a restart the
  newest file of the day is continued.
- Retention: `audit.max_files` rotated files are kept besides the current one;
  older files are deleted at rotation time. `0` (default) keeps everything.
  Archive or ship the directory yourself if you need longer history than you
  keep.
- Durability: each event is written with one `write` call immediately (it
  survives a process crash). `fsync` runs about once a second, at every
  rotation and on clean shutdown, so a clean shutdown loses nothing.
- Failure behaviour: an audit failure never changes the outcome of the audited
  operation. If the disk is full or the directory is unwritable the event is
  dropped, an error is logged, `tlsbroker_audit_write_failures_total`
  increases, and the next event tries again. A partial last line (crash, full
  disk) is ended with a newline by the next writer and skipped by readers.

### Who sees what in the UI

| Viewer | Sees |
|---|---|
| Logged-in user | events with `visibility: public`: full source IP, username, names and wildcards, timestamps, provider and result of gate decisions, orders, issuances, direct fetches, DNS present/cleanup, logins |
| Admin | everything: additionally denied requests, grant changes, role changes, blocks, LDAP/config errors, rate-limit events, provider state and failover |

An event without `visibility` is admin-only, so forgetting to classify an event
fails closed. The UI filters by time range, type, mode and a case-insensitive
substring that matches source IP, names, username, provider, reason and detail
(this is how decision, identifier, IP and username filters are expressed);
results are newest first, capped at 200 by default.

## Metrics

`GET /metrics`, Prometheus text format, served by `metrics.Metrics.Handler()`.
It has no authentication: restrict it (see the nginx snippet). Label values
come from small closed sets; identifiers, IPs and usernames are never labels
(the one exception is `identifier` on the certificate expiry gauge, bounded by
the direct-mode cache).

| Metric | Type | Labels | Meaning |
|---|---|---|---|
| `tlsbroker_requests_total` | counter | `mode`, `outcome` | front-end requests; outcome `ok`, `denied`, `rate_limited`, `unavailable`, `error` |
| `tlsbroker_gate_decisions_total` | counter | `mode`, `decision`, `reason` | gate decisions by reason |
| `tlsbroker_issuance_total` | counter | `provider`, `mode`, `class`, `result` | finished issuance attempts; `class` is the priority class (`ari_renewal`, `direct_emergency`, `acme_emergency`, `acme_ordinary`, `direct_miss`, `direct_background`) |
| `tlsbroker_issuance_duration_seconds` | histogram | `provider`, `mode` | admission to end of attempt |
| `tlsbroker_upstream_errors_total` | counter | `provider`, `kind` | failed CA calls; kind `rate_limited`, `busy`, `down`, `rejected`, `already_replaced` |
| `tlsbroker_scheduler_slots_in_use` / `_slots_total` | gauge | `provider` | concurrency slots |
| `tlsbroker_scheduler_waiters` | gauge | `provider` | requests waiting for a slot |
| `tlsbroker_scheduler_reservations` | gauge | `provider` | open budget reservations |
| `tlsbroker_scheduler_circuit_open` | gauge | `provider` | 1 while admission is closed (rate limited or down) |
| `tlsbroker_scheduler_provider_state` | gauge | `provider`, `state` | 1 for the current state `healthy`, `rate_limited`, `down` |
| `tlsbroker_scheduler_budget_used` / `_budget_limit` / `_budget_remaining` | gauge | `provider`, `kind`, `key` | sliding-window budgets (`new_order`, `cert_domain`, `cert_set`); only buckets with usage are listed |
| `tlsbroker_dns01_present_duration_seconds` | histogram | | DNS-01 present including propagation |
| `tlsbroker_dns01_failures_total` | counter | `op` | `present` and `cleanup` failures |
| `tlsbroker_direct_cache_total` | counter | `result` | `hit` or `miss` on direct fetches |
| `tlsbroker_direct_renewals_total` | counter | `result` | background renewals, `ok` or `failed` |
| `tlsbroker_cert_not_after_timestamp_seconds` | gauge | `identifier` | expiry of each cached direct-mode certificate |
| `tlsbroker_audit_write_failures_total` | counter | | audit events that could not be written |
| `tlsbroker_build_info` | gauge | `version`, `go_version` | always 1 |
| `go_*`, `process_*` | | | Go runtime and process collectors |

Scheduler metrics are read from the scheduler's in-memory snapshot at scrape
time; a scrape does no I/O. The issuance engine, the DNS-01 engine and the
upstream adapter take no recorder: `internal/app` counts `issuance_*` from
the engine's `issue` audit events (class and admission time from the order
row), `upstream_errors_*` from every failed provider call, and `dns01_*`
around the DNS engine port.

### Suggested alerts

```yaml
groups:
- name: tls-broker
  rules:
  - alert: BrokerProviderCircuitOpen
    expr: tlsbroker_scheduler_circuit_open == 1
    for: 10m
    annotations: {summary: "Upstream CA {{ $labels.provider }} has been refused admission for 10 minutes"}
  - alert: BrokerBudgetLow
    expr: tlsbroker_scheduler_budget_remaining{kind="new_order"} / tlsbroker_scheduler_budget_limit{kind="new_order"} < 0.1
    for: 5m
    annotations: {summary: "New-order budget of {{ $labels.provider }} is below 10%"}
  - alert: BrokerCertNearExpiryNotRenewed
    expr: tlsbroker_cert_not_after_timestamp_seconds - time() < 5 * 86400
    for: 1h
    annotations: {summary: "Cached certificate for {{ $labels.identifier }} expires in under 5 days"}
  - alert: BrokerAuditWriteFailures
    expr: increase(tlsbroker_audit_write_failures_total[10m]) > 0
    annotations: {summary: "Audit events are being lost; check disk space under <data>/audit"}
  - alert: BrokerDown
    expr: up{job="tls-broker"} == 0
    for: 2m
```

Tune the expiry threshold to your renewal fraction: a direct-mode entry is
renewed only when a client fetches it, so an idle identifier near expiry is
expected to alert.

## /healthz

`GET /healthz` (also `HEAD`) answers whether the broker process can take
traffic. It reflects readiness only and never upstream CA health, so a CA
outage does not make orchestration restart the broker.

| Status | Body | Meaning |
|---|---|---|
| 200 | `{"status":"ok"}` | startup finished (recovery done) and the database answers a ping |
| 503 | `{"status":"starting"}` | not ready yet |
| 503 | `{"status":"unavailable","reason":"database"}` | database ping failed or timed out (2 s) |
| 503 | `{"status":"shutting_down"}` | shutdown begun; stop sending traffic |

Error text is never included. The app marks the broker ready after
startup recovery (issuance `Recover`, direct cache `Verify`) and clears it
first thing on shutdown (`httpx.Health.SetReady`); while not ready every path
except `/healthz` and `/metrics` answers 503.

## Real source address

`internal/httpx` derives the source IPv4 once per request (architecture §19).
The configured real-IP header (default `X-Real-IP`) is believed only when the
TCP peer is inside `server.trusted_proxies`; from any other peer the header is
ignored and the TCP peer is the source. `X-Forwarded-For` is never read. The
header must hold exactly one IPv4 address (an IPv4-mapped IPv6 address is
accepted as IPv4); several values, a list, garbage or a non-IPv4 address leave
the source invalid and the request is denied with `not_ipv4`. If a trusted
proxy omits the header, the proxy's own address is used and the access log
carries `ip_flag=header_missing`: fix the proxy configuration.
"The client used https" is derived the same way from `X-Forwarded-Proto`.

The access log (`log/slog`, JSON or text per the app) has one line per request
with method, path (never the query string), status, bytes, duration,
`source_ip`, `request_id` and user agent. `X-Request-ID` is returned on every
response; a well-formed inbound one is kept only from a trusted proxy.

## nginx

```nginx
# Real address: overwrite, never append, whatever the client sent.
location / {
    proxy_pass         http://127.0.0.1:8080;
    proxy_set_header   X-Real-IP          $remote_addr;
    proxy_set_header   X-Forwarded-Proto  $scheme;
    proxy_set_header   X-Request-ID       $request_id;
    proxy_set_header   X-Forwarded-For    "";    # the broker ignores it anyway
    proxy_read_timeout 300s;                    # held ACME / direct requests
    client_max_body_size 1m;
}

# Metrics: only the Prometheus host, never the LAN.
location = /metrics {
    allow 10.0.0.10;      # Prometheus
    deny  all;
    proxy_pass http://127.0.0.1:8080;
    proxy_set_header X-Real-IP $remote_addr;
}
```

Set `server.trusted_proxies` to the address nginx connects from (for example
`127.0.0.1/32`, or the docker bridge gateway when nginx runs outside the
container) and keep the broker's listener unreachable from the LAN, otherwise
any host could forge the header from a trusted-looking path.
