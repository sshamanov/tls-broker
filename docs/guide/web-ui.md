# Using the web interface

The web interface is at `https://broker.example.com/ui/`. Log in with your
directory (LDAP) account. It shows what the broker is doing and lets you
manage which machines may request certificates. The pages below are what
every user sees; administrators get more (see [Roles](#roles)).

## Status

The start page. It shows:

- **Certificate authorities**: whether each CA is *operational*, *degraded*
  (working, but recent answers were errors or rate limits) or *unavailable*
  (with the time the broker tries again).
- **Queue**: orders in progress and requests waiting for their turn.
- **Rate-limit headroom**: how much of each CA's limits is used. *Caution*
  from 75 %, *exhausted* when nothing is left; new requests then wait or are
  refused until the window moves on.
- **Recent issuance** and **Expiring next**: the latest results and the
  certificates that expire soonest.

## Certificates

Every certificate the broker obtained, in two lists:

- **Issued to ACME clients**: certificates of ACME-proxy clients. Each row
  shows the names, the **owner**, the CA, serial, validity and whether it
  was replaced by a renewal.
- **Direct cache**: certificates the broker keeps for direct download,
  with the last fetch time and address and the next renewal.

The **owner** is the user whose client access entry allowed the request,
with that entry's address. "No owner, DNS match from" means the names
resolved to the requesting machine and no entry was needed.

The **lifetime bar** runs from issue (left) to expiry (right). The tick marks
when renewal is due, the vertical line is now. The filled part is blue while
the certificate is fine, brass once renewal is due and red when it has
expired.

Filter by name, CA, kind, and whether to include expired certificates.

## Client access

The list of addresses allowed to request certificates, with their owner.
Filter it to show everyone's entries, only yours, or one user's.

To give your machine access:

1. Find the machine's IPv4 address as the broker sees it (the address it
   uses to reach the broker, not a public NAT address).
2. Enter it under **Add address** (`10.1.2.3` or `10.1.2.3/32`), with a note that says what the machine
   is.
3. Tick **Allow wildcard certificates** only if the machine needs `*.`
   certificates. The box appears only for users with the wildcard role and
   administrators.

You can disable, enable and delete your own entries; a disabled entry stays
in the list but allows nothing. Entries keep working when their owner leaves
or is blocked, so delete the ones you no longer need.

## Activity log

Every certificate request with its outcome: allowed or denied (and why),
orders admitted or refused, certificates issued or failed, DNS-proxy records
published, and client access changes. Search by address, name, user or
reason, and filter by type, mode and date. When a request fails, look here
first; [Troubleshooting](troubleshooting.md) explains the reasons.

## Roles

| Role | Can |
|---|---|
| user | see status, certificates, client access and activity; add single-address entries and manage their own |
| user with wildcards | the same, and allow wildcards on their entries |
| administrator | everything, plus address ranges (/8 to /32) and anyone's entries, and the pages below |
| blocked | read only: own client access entries, the activity log and this documentation |

Administrators additionally see:

- on **Status**: problems that need attention, CA details and all rate-limit
  budgets, the broker's CA account URLs, the managed DNS zones and whether
  their CAA records protect wildcards;
- **Users**: set roles, block and unblock accounts;
- **CAs**: the state, limits and accounts of each certificate authority;
- **Configuration**: the broker's settings, validated before they are
  activated, with history and roll back;
- **Secrets**: credentials the configuration refers to (write only);
- in the activity log: every event type with technical detail.
