# Route53 DNS-01 engine

Every upstream certificate the broker obtains is validated with DNS-01
through Route53 (architecture §17). The same engine serves the DNS proxy
(`/dns/present`, `/dns/cleanup`). This page explains how a challenge flows,
what the broker needs from AWS, the settings, restart behaviour and
troubleshooting. Code: `internal/dns01`.

## How a challenge flows

A challenge is one TXT value at one record name, always
`_acme-challenge.<name>`. A wildcard and its base name share the record
(`*.foo.example.com` and `foo.example.com` both use
`_acme-challenge.foo.example.com`). Several challenges may use the same
record at once, from different orders, owners or the DNS proxy.

**The engine never overwrites a value it does not own.** For each record name
the RRset it writes is:

```text
values Route53 already has that no active broker challenge owns   (foreign)
+ values of the record's challenges that want a record             (pending,
                                                                    presenting,
                                                                    waiting_dns,
                                                                    ready)
```

Values of challenges being cleaned up are left out; everything else in the
RRset is kept verbatim. When nothing remains, the RRset is deleted.

`Present(owner, record, value)`:

1. Picks the managed zone by longest suffix (`sub.example.com` wins over
   `example.com`). A record outside every managed zone, or a name that is not
   an `_acme-challenge` record, is refused (`outside managed zones`) and
   nothing is recorded.
2. If a non-terminal challenge with the same owner, record and value exists,
   it is reused (idempotent; this is how preparation resumes after a
   restart). Otherwise a challenge row is created in state `pending`.
3. `presenting`: the record name is queued on the zone's write queue (below).
4. `waiting_dns`: the change is submitted. The engine now polls the public
   resolver (DoH) until the exact value is visible; it does **not** wait for
   Route53 `INSYNC` first. While the value is still invisible it also asks
   Route53 for the change status.
5. `ready`: the value is visible; `Present` returns the challenge ID.

If anything fails after the row exists (Route53 error, timeout, caller gave
up), the value is removed again and the challenge ends `failed` with the
reason in its error text.

`Cleanup(id)` moves the challenge to `cleaning`, rewrites the record without
its value and marks it `done`. Cleaning a finished challenge is a no-op.
`CleanupOwner(owner)` cleans every active challenge of an owner (all removals
in one zone go into one change).

### Write queue per hosted zone

All writes to one hosted zone go through one serialized queue; different
zones are written in parallel. A write does not carry a value: it carries a
record name, and the RRset is computed from the challenge rows and the
current Route53 data at the moment the write runs. Every record name queued
while a change is in flight is written together in the next change (up to 50
names per change), so a burst of challenges costs few Route53 calls.

Each record is changed with `DELETE` (the exact current RRset) plus `CREATE`
(the new one) in one atomic batch. If someone else changed the RRset between
the read and the write, Route53 rejects the batch and the engine reads again
and retries (three attempts), so a concurrent foreign edit is never lost.

Values are written as quoted TXT strings (split into 255-byte strings when
longer, `"` and `\` escaped) with the configured TTL (60 s by default).

### Timing

| Phase | Bound |
|---|---|
| One Route53 API call | 30 s, then retried |
| Write of a batch (read, change, retries) | `route53.change_timeout` |
| Change reaching `INSYNC` while the value is still invisible | `route53.change_timeout` from submission |
| Value becoming visible after `INSYNC` | `route53.propagation_timeout` |
| Visibility poll interval | starts at `route53.poll_interval`, grows ×1.5 up to 4× |

Throttling (`Throttling`, `ThrottlingException`, `PriorRequestNotComplete`),
Route53 server errors, transport errors and call timeouts are retried with
exponential backoff (0.5 s doubling to 10 s) until the batch bound. Other
errors (access denied, invalid input, missing zone) fail at once. All waiting
uses the broker clock.

Errors `Present` returns: `outside managed zones`; `TXT record did not become
visible in public DNS` (propagation timeout); `route53 change did not complete
in time` (write or `INSYNC` exceeded `change_timeout`); the Route53 error;
cancellation; `engine is closed` during shutdown.

## Settings

In the configuration YAML (see `docs/configuration.md`):

```yaml
zones:
  - name: example.com
    hosted_zone_id: Z0123456789ABCDEFGHIJ
route53:
  region: us-east-1               # Route53 is global; the region only selects the endpoint
  access_key_id_secret: ""        # both or neither, see Credentials
  secret_access_key_secret: ""
  ttl: 60s                        # TTL of challenge TXT records
  change_timeout: 2m
  propagation_timeout: 2m
  poll_interval: 2s
```

Zones and timeouts are read on every call, so a configuration change applies
to the next challenge. The startup check (`VerifyZones`) confirms every
configured hosted zone exists, has the configured name and is public (a
private zone is invisible to the public resolvers the CAs use).

## Credentials

Two options:

- **Secrets.** Set `route53.access_key_id_secret` and
  `route53.secret_access_key_secret` to the names of two secrets (for example
  `route53-access-key-id` / `route53-secret-access-key`) and enter the values
  in the UI. They are read when the broker starts and re-read every five
  minutes, so a rotated key is picked up without a restart. A missing or
  empty secret is a startup error.
- **Default AWS credential chain.** Leave both names empty: environment
  (`AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, `AWS_SESSION_TOKEN`,
  `AWS_PROFILE`), shared config/credentials files, web identity, ECS
  container credentials or the EC2 instance role, in the SDK's usual order.
  Prefer a role when the broker runs on AWS.

## IAM policy

Grant exactly this, with your hosted zone IDs. The change permission is
limited by Route53's condition keys to `TXT` records named
`_acme-challenge.*`, and to the `CREATE`/`DELETE` actions the engine uses.
`ListResourceRecordSets` cannot be restricted by record name; it is
read-only.

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "ChallengeTXTOnly",
      "Effect": "Allow",
      "Action": "route53:ChangeResourceRecordSets",
      "Resource": [
        "arn:aws:route53:::hostedzone/Z0123456789ABCDEFGHIJ",
        "arn:aws:route53:::hostedzone/Z9876543210JIHGFEDCBA"
      ],
      "Condition": {
        "ForAllValues:StringLike": {
          "route53:ChangeResourceRecordSetsNormalizedRecordNames": ["_acme-challenge.*"]
        },
        "ForAllValues:StringEquals": {
          "route53:ChangeResourceRecordSetsRecordTypes": ["TXT"],
          "route53:ChangeResourceRecordSetsActions": ["CREATE", "DELETE"]
        }
      }
    },
    {
      "Sid": "ReadZones",
      "Effect": "Allow",
      "Action": ["route53:ListResourceRecordSets", "route53:GetHostedZone"],
      "Resource": [
        "arn:aws:route53:::hostedzone/Z0123456789ABCDEFGHIJ",
        "arn:aws:route53:::hostedzone/Z9876543210JIHGFEDCBA"
      ]
    },
    {
      "Sid": "ChangeStatus",
      "Effect": "Allow",
      "Action": "route53:GetChange",
      "Resource": "arn:aws:route53:::change/*"
    }
  ]
}
```

`_acme-challenge.*` in the condition matches challenge records at any depth
(the normalized names are lower case without trailing dot). Because the
broker only ever writes `_acme-challenge` records, it refuses any other
record name itself as well.

## Restart and reconciliation

The engine keeps no queue across restarts; the challenge rows in SQLite are
the state. At startup `Reconcile` rebuilds the desired RRset of every record
that has non-terminal challenges and writes Route53 to match:

| Row left by the crash | After reconcile |
|---|---|
| `pending`, `presenting`, `waiting_dns`, `ready` | value present in Route53; row unchanged. The next `Present` for the same owner, record and value picks it up and waits for visibility; a cleanup removes it. |
| `cleaning` after a cleanup | value removed; row `done` |
| `cleaning` after a failed present (error text starts with `present:`) | value removed; row `failed` |
| `done`, `failed` | not looked at |

Values with no active row are never touched: the broker cannot tell an old
value of its own from someone else's. Run `Reconcile` again at any time; when
Route53 already matches it writes nothing.

Shutdown: the engine stops accepting work, `Present` calls waiting for
visibility return at once, and writes already queued get the shutdown grace
to finish. A challenge interrupted this way is left non-terminal (normally
`cleaning` with its error) and is repaired by the next start's `Reconcile`.

DNS-proxy challenges that their client never cleans up are removed by the DNS
proxy after `dns_proxy.challenge_ttl` (it lists stale rows and calls
`Cleanup`); the engine itself never relies on DNS TTLs for cleanup.

## Troubleshooting

| Symptom | Likely cause and fix |
|---|---|
| `AccessDenied` on `ChangeResourceRecordSets` | IAM policy missing the zone ARN, or the record is not `_acme-challenge.*` TXT. Check the policy above. |
| `NoSuchHostedZone`, or startup says the zone name does not match | Wrong `hosted_zone_id` in the configuration, or the ID belongs to another account. |
| Startup says a zone is private | The configured ID is a private hosted zone; use the public zone with the same name. |
| `route53 change did not complete in time` | Route53 is throttling or unreachable for longer than `change_timeout`, or the change stayed `PENDING`. Check AWS service health and other tools writing to the same account (Route53 limits API calls per account). |
| `TXT record did not become visible in public DNS` | The change is in sync but the public resolvers do not see it: the domain's NS delegation does not point to this hosted zone, a more specific zone (or a CNAME at `_acme-challenge`) exists elsewhere, or negative caching from an earlier lookup. `dig +trace TXT _acme-challenge.<name>` and compare the NS set with the hosted zone's delegation set. Raise `propagation_timeout` only if it eventually appears. |
| `name is outside managed zones` | The name has no managed zone; add the zone, or it is not an `_acme-challenge` record. |
| A challenge stays `cleaning` | Removal failed (its error text says why); it is retried by the next `Reconcile` (startup) or by calling cleanup again. |
| Unexpected values remain at a record | They are not owned by an active challenge (foreign, or left after a manual edit); the broker never removes them. Delete them by hand if they are yours. |
