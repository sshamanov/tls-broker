# Upstream CA providers

The broker obtains every certificate from a public ACME CA. Each configured
**provider** is one account at one CA (architecture §9). The first enabled
provider is the primary; the others are fallbacks used only when the primary
cannot serve (new issuance) or in an emergency (renewal). The code is in
`internal/upstream`: `ACMEProvider` implements `core.Provider`, `Registry`
implements `core.Providers`.

## Provider configuration

A provider is a `core.ProviderConfig`; the YAML spelling of the fields is in
`docs/configuration.md`.

| Field | Meaning |
|---|---|
| `Name` | Stable local name (`letsencrypt`). Stored with orders and certificates and in the secret names below; never reuse a name for another CA. |
| `Disabled` | Defined but not used for new issuance or renewal. A disabled provider still answers renewal information for certificates it issued. |
| `DirectoryURL` | ACME directory. Must be `https://`. |
| `Contact` | Account e-mail, optional (`mailto:` is added). |
| `EABKeyID`, `EABSecretName` | External account binding: the key id, and the name of the secret holding the MAC key (base64url, as the CA prints it). Both or neither. |
| `Profile` | ACME profile sent in every newOrder; empty for the CA's default. |
| `CAAIssuers` | CAA issuer domains of the CA (`letsencrypt.org`, `pki.goog`). Used by the CAA checks in the gate and UI. |
| `AccountURIHonoured` | The CA enforces the RFC 8657 `accounturi` CAA parameter. Needed for DNS-proxy wildcard protection (architecture §3.2). |
| `ARI` | The CA serves renewal information and accepts `replaces`. |
| `ARIExempt` | A `replaces` order inside the suggested window is exempt from the CA's rate limits. Decides whether a renewal can be ARI-qualified (priority 1, budget-exempt). |
| `Limits` | Local budgets for the scheduler, see `docs/rate-limits.md`. |

The shared `Upstream` section sets the timeouts for all providers:
`HTTPTimeout` (one HTTP request, default 30 s), `ValidationTimeout` (how long
`WaitReady` polls, 2 min), `IssueTimeout` (how long `WaitCertificate` polls,
2 min), `PollInterval` (pause between polls when the CA sends no
`Retry-After`, 2 s).

Every request carries `User-Agent: tls-broker/<version>` (followed by
lego's own token).

### Presets

`upstream.Presets()` holds the well-known CAs with every CA fact filled in;
the operator adds contact, EAB and profile.

| Preset | Directory | CAA issuer | ARI | ARIExempt | accounturi | EAB |
|---|---|---|---|---|---|---|
| `letsencrypt` | `https://acme-v02.api.letsencrypt.org/directory` | `letsencrypt.org` | yes | yes | yes | no |
| `letsencrypt-staging` | `https://acme-staging-v02.api.letsencrypt.org/directory` | `letsencrypt.org` | yes | yes | yes | no |
| `google` | `https://dv.acme-v02.api.pki.goog/directory` | `pki.goog` | yes | **no** | **no** | required |
| `google-staging` | `https://dv.acme-v02.test-api.pki.goog/directory` | `pki.goog` | yes | **no** | **no** | required |

Limits: Let's Encrypt presets use `core.DefaultProviderLimits()` (below
300 new orders / 3 h, 50 certificates per registered domain / 7 d, 5 per exact
set / 7 d). Google presets lower new orders to 60 / hour (the CA allows 100
newOrder per hour per project).

Staging CAs issue untrusted certificates; use them to rehearse, never as a
fallback for real clients.

The registry follows configuration reloads. A provider whose definition (and
the shared timeouts) did not change keeps its instance; a changed one is
rebuilt and reads its account from the secret store again.

## Setting up Let's Encrypt

1. Add a provider from the `letsencrypt` preset with a contact address.
2. Publish CAA for every managed zone (see below).
3. Nothing else: the account key is generated and the account registered on
   first use. The account URL is shown in the UI; it is what goes into
   `accounturi`.

Rehearse with `letsencrypt-staging` first; it is a different CA with a
different account, so give it its own provider name.

## Setting up Google Trust Services

Google requires external account binding. EAB keys are created per Google
Cloud project, are **single-use** and must be used within **7 days**:

```sh
gcloud services enable publicca.googleapis.com --project <project>
gcloud publicca external-account-keys create --project <project>
# prints keyId and b64MacKey
```

For staging, point gcloud at the staging API first:

```sh
gcloud config set api_endpoint_overrides/publicca https://preprod-publicca.googleapis.com/
gcloud publicca external-account-keys create --project <project>
gcloud config unset api_endpoint_overrides/publicca
```

Then:

1. Store `b64MacKey` as a secret (for example `eab-google`) in the UI.
2. Add a provider from the `google` preset with `EABKeyID` = `keyId` and
   `EABSecretName` = `eab-google`.
3. The broker registers on first use with the EAB binding and keeps the
   account key. Because the EAB key cannot be used again, **losing the account
   key means creating a new EAB key**; back it up (below).

If the secret is missing the provider refuses locally with
`externalAccountRequired` and sends nothing. Google validates each challenge
once and does not retry, which is why the broker accepts a challenge only
after its TXT record is visible in public DNS.

## Profiles

`Profile` is sent as `profile` in every newOrder (draft-ietf-acme-profiles);
empty sends nothing and the CA picks its default. Let's Encrypt offers
`classic` (default, 90 days), `tlsserver` (server-auth only, no common name)
and `shortlived` (about six days). Certificate lifetime feeds the emergency
window (architecture §8), so a short-lived profile shrinks the time the broker
will wait on a broken primary before switching. A profile the CA does not
know is refused (`invalidProfile`, class `rejected`).

## ARI and `replaces`

ARI (RFC 9773) tells a client when to renew; `replaces` in a newOrder tells
the CA which certificate the order succeeds.

- `RenewalInfo(certID)` GETs the CA's renewal information (no account needed)
  and returns the suggested window, the explanation URL and the CA's
  `Retry-After` (seconds or HTTP date).
- `NewOrder(names, replaces)` sends `replaces` when it is not empty. A
  provider without `ARI`, or whose directory has no `renewalInfo`, refuses a
  non-empty `replaces` locally (`rejected`, nothing sent).
- Let's Encrypt exempts a `replaces` order from rate limits only inside the
  predecessor's suggested window, from the same account. Google documents no
  exemption, so its presets set `ARIExempt` false and its renewals use
  ordinary budget. The flag is per provider; set it only for a CA that
  documents the exemption.
- A certificate can have only one live replacement order. The second gets
  `alreadyReplaced` (HTTP 409), class `already_replaced`; the adapter never
  creates an order in that case (lego would silently retry without
  `replaces`; the adapter suppresses that retry) and the issuance engine
  retries once without `replaces`.

ARI continuity depends on keeping the account: the exemption requires the
same account that obtained the predecessor.

## CAA records

Every managed zone must authorize every enabled provider, or a fallback
cannot issue when it is needed:

```text
example.com.  CAA 0 issue     "letsencrypt.org; accounturi=https://acme-v02.api.letsencrypt.org/acme/acct/123456789"
example.com.  CAA 0 issuewild "letsencrypt.org; accounturi=https://acme-v02.api.letsencrypt.org/acme/acct/123456789"
example.com.  CAA 0 issue     "pki.goog"
example.com.  CAA 0 issuewild "pki.goog"
```

- `accounturi` pins issuance to the broker's account. Use it for every CA with
  `AccountURIHonoured`; it is what makes DNS-proxy mode safe for zones whose
  grants do not allow wildcards (architecture §3.2). The account URL is shown
  in the UI once the provider has registered.
- Google's `accounturi` support is unconfirmed, so its presets set
  `AccountURIHonoured` false and the gate does not count a `pki.goog` record
  as protection.
- If you publish `issuewild` at all, include every provider there too.

## Error classes

Every provider call returns nil, the context's error, or a
`*core.ProviderError` whose `Kind` is decided only from status codes, problem
types and headers:

| Answer from the CA | Kind | Effect (scheduler, issuance) |
|---|---|---|
| `rateLimited` problem, or HTTP 429 | `rate_limited` | Circuit closed until `Retry-After` (else `RateLimitRetryAfter`); downstream 429. |
| HTTP 503, or `serverInternal`, **with** `Retry-After` | `busy` | Short back-off for `Retry-After`; downstream 503 with Retry-After. |
| Connection error, TLS error, timeout, other 5xx, `serverInternal` without `Retry-After`, `badNonce` still failing after retries | `down` | Circuit open with exponential back-off (`DownRetryAfter` .. `DownRetryAfterMax`); next provider for new issuance. |
| `alreadyReplaced` (409) | `already_replaced` | Retry once without `replaces`. Not a health signal. |
| Any other 4xx problem; an order/authorization that became invalid | `rejected` | Request fails with the CA's problem (type, detail, status, subproblems preserved). Not a health signal. |

`Retry-After` is parsed in both forms (delay seconds and HTTP date, measured
from the broker's clock), capped at 30 days, and set on the error as
`RetryAfter`. `badNonce` is retried transparently (lego's back-off, at most
20 s) and never reaches callers unless it persists. The provider never retries
anything else: retries are policy, decided by the scheduler and the issuance
engine.

Local failures that make a provider unusable (unreadable secret store, a
corrupt stored account key) are reported as `down` with the cause in `Err`.

Polling (`WaitReady`, `WaitCertificate`) honours the CA's `Retry-After` on
order answers, else waits `PollInterval`, and gives up with `down` when its
timeout passes; calling it again continues waiting. `Finalize` reads the
order first, so repeating it for an order that is already processing or valid
returns the current state without a second submission (for a valid order the
certificate key must match the CSR's, otherwise `orderNotReady`).
`WaitCertificate` returns the leaf followed by the intermediates; a root the CA
includes is dropped.

## Account keys

| Secret | Content |
|---|---|
| `provider-account-key.<name>` | Account private key, PEM. Generated (ECDSA P-256, PKCS#8) on first use. |
| `provider-account-url.<name>` | Account URL after registration. |
| your EAB secret | EAB MAC key, base64url. |

- The key is **never regenerated** while the secret exists. An unreadable key
  is an error (`down`), not a reason to make a new one.
- A lost account URL is recovered automatically: the same key is registered
  again and the CA returns the existing account.
- A stored URL whose host differs from the current directory (the provider was
  pointed at another CA) is ignored and the key registered at the new CA.
- Keys can be imported: PKCS#8 (`PRIVATE KEY`), SEC 1 (`EC PRIVATE KEY`) or
  PKCS#1 (`RSA PRIVATE KEY`) PEM in `provider-account-key.<name>`.

Back up `<data>/secrets/` with the rest of the data root (architecture §23).
Losing a key loses ARI continuity and the CAA `accounturi` pin; with Google it
also needs a new EAB key.

## Testing

Unit tests (`scripts/dev go test -race ./internal/upstream/...`) run against
an in-test ACME server (`stub_test.go`) that verifies JWS signatures, nonces
and EAB bindings, and cover every method, every error class, both
`Retry-After` forms, `badNonce` retries, `replaces`/`profile` payloads,
repeated finalize and account reuse across instances. `TestBehavesLikeFakeCA`
runs one scenario against `coretest.FakeCA` and the real adapter.

### Testing against Pebble

`pebble_test.go` (build tag `pebble`) runs the full flow against a real
Pebble: registration, wildcard + base order, dns-01 via challtestsrv,
finalize twice, chain without root, renewal information, `replaces` and
`alreadyReplaced`, explicit profiles. It is skipped unless
`TLS_BROKER_PEBBLE_DIRECTORY` is set. `test/pebble.sh` starts Pebble and
challtestsrv (see `docs/development.md`, "Pebble"):

```sh
test/pebble.sh start      # writes .claude/tmp/e2e/pebble.minica.pem
scripts/dev env \
  TLS_BROKER_PEBBLE_DIRECTORY=https://127.0.0.1:14000/dir \
  TLS_BROKER_PEBBLE_ROOT=/src/.claude/tmp/e2e/pebble.minica.pem \
  TLS_BROKER_PEBBLE_CHALLTESTSRV=http://127.0.0.1:8055 \
  go test -race -tags pebble -run TestPebble -count=1 -v ./internal/upstream/
test/pebble.sh stop
```

Host ports used: 14000/15000 (Pebble) and 8055 (challtestsrv management);
challtestsrv's DNS (8053) stays inside the containers' network.
Pebble without a `profile` picks one of its profiles itself, so the test
requests `default` and `shortlived` explicitly when it checks lifetimes.

## Implementation notes

The adapter uses lego's low-level `acme/api` package. Two lego behaviours are
worked around in `transport.go`: errors do not expose response headers (a
per-call capture in the HTTP transport records status and `Retry-After`), and
`Orders.New` retries without `replaces` after `alreadyReplaced` (the capture
refuses any further request in that call). lego requires HTTPS, so test
servers use TLS with a custom root pool (`Options.RootCAs`).
