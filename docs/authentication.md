# Authentication

Package `internal/auth` authenticates humans for the web UI. Machines are never
authenticated by it: ACME and direct mode are gated by source IP
(`docs/authorization.md`). Design background: `architecture.md` §4 and §5.

## Who can log in

1. The **local break-glass admin** (environment), checked first.
2. Any user LDAP accepts. LDAP is the only source of identity; it never
   defines roles.

A user row is created locally at the first successful login with role
`normal`. Usernames are trimmed and lower-cased everywhere. The break-glass
name is reserved: a login with that username is only ever checked against the
local password. A wrong password is "invalid credentials" (and counts for the
throttle); it is never tried against LDAP, so a mistyped break-glass password
does not travel to the directory and an LDAP account of the same name cannot
log in through the UI. Pick a break-glass name that no directory user has.

## LDAP setup

Settings live in the `ldap:` section of the YAML configuration (edited in the
UI, tested before a generation is activated):

| Field | Meaning |
|---|---|
| `url` | `ldaps://host:636` or `ldap://host:389`. Empty means LDAP is not configured. |
| `bind_dn` | Service account used to search for the user. Empty means an anonymous search. |
| `bind_password_secret` | Name of the secret holding the service account password (set it in the UI; it is never in the YAML). |
| `base_dn` | Where to search (whole subtree). |
| `user_filter` | Search filter; `%s` is replaced by the username, escaped. |
| `starttls` | Upgrade an `ldap://` connection with StartTLS. Ignored for `ldaps://`. |
| `insecure_skip_verify` | Skip server certificate verification. Avoid. |
| `timeout` | Per-operation timeout (default 10 s). |

Login does: connect (TLS verified against the system roots, or against the CA
pool the daemon was built with), bind as the service account, search with the
filter, require **exactly one** entry, then bind as that entry's DN with the
password the user typed. Zero or several matches, a wrong password and an
empty password are all "invalid credentials". An empty password is rejected
before any connection is made, because many servers treat a DN bind with an
empty password as a successful anonymous bind.

The username is escaped with RFC 4515 rules before it enters the filter, so
`*)(uid=*` cannot widen the search. The filter must contain `%s` and be valid
once substituted; otherwise LDAP counts as unavailable.

Filter examples:

```yaml
# OpenLDAP, users in ou=people, log in with uid
ldap:
  url: ldaps://ldap.example.com:636
  bind_dn: cn=svc-broker,dc=example,dc=com
  bind_password_secret: ldap-bind
  base_dn: ou=people,dc=example,dc=com
  user_filter: "(&(objectClass=inetOrgPerson)(uid=%s))"

# Active Directory, log in with sAMAccountName, only members of a group,
# disabled accounts excluded
ldap:
  url: ldaps://dc1.corp.example.com:636
  bind_dn: CN=svc-broker,OU=Service,DC=corp,DC=example,DC=com
  bind_password_secret: ldap-bind
  base_dn: DC=corp,DC=example,DC=com
  user_filter: "(&(objectClass=user)(sAMAccountName=%s)(!(userAccountControl:1.2.840.113556.1.4.803:=2))(memberOf=CN=tls-broker,OU=Groups,DC=corp,DC=example,DC=com))"
```

Because the user must match the filter, group membership checks belong in the
filter. The filter is evaluated at login only.

**Testing.** Before a configuration generation with new LDAP settings is
activated, the broker connects, binds with the service account and runs the
filter for a probe name. Finding nobody is fine; an unreachable server, a
rejected service bind, a missing secret, a bad base DN or an invalid filter
fail the validation and the generation is not activated.

## Roles and blocked

Roles (`admin` > `wildcard_allowed` > `normal`) and the `blocked` switch are
local state, changed by admins in the UI. A blocked user can still log in (so
they can see the views allowed to blocked users) but has no rights: the UI
must check `User.Blocked` / `User.Can(role)`. Because every request re-reads
the user, a role change or block applies to existing sessions immediately.

## Bootstrap administrators

Roles are local, so the first admin comes from the environment. Both
mechanisms are optional.

- `TLS_BROKER_ADMINS` - comma-separated LDAP usernames. They get role `admin`
  on every login (a demotion in the UI is undone at their next login; removing
  a name from the list does not demote anyone).
- `TLS_BROKER_LOCAL_ADMIN_USER` and `TLS_BROKER_LOCAL_ADMIN_PASSWORD` - a
  break-glass admin that does not use LDAP. It works with LDAP down or not yet
  configured, is always `admin`, and cannot be blocked: a stored `blocked`
  flag or lower role is reset at login. It is stored as a user with `Local`
  set. Without a password the account is disabled.

The password is either plain or a bcrypt hash (a value starting with `$2`).
Compare is constant time. Prefer a hash; generate one with:

```sh
htpasswd -nbBC 12 "" 'the-password' | tr -d ':\n' | sed 's/^\$2y/$2a/'
# without apache2-utils installed:
docker run --rm httpd:2 htpasswd -nbBC 12 "" 'the-password' | tr -d ':\n' | sed 's/^\$2y/$2a/'
```

In a compose `.env` file or a shell, `$` characters must be escaped (`$$2a$$12$$...`
in compose) or the value single-quoted.

## Sessions

- A successful login returns an opaque random token (256 bits) set in an
  `HttpOnly`, `SameSite=Strict` cookie, `Path=/`. `Secure` follows
  `sessions.cookie_secure`: `auto` (default) sets it when the request arrived
  over TLS (directly, or through the trusted proxy with https), `always`
  sets it on every cookie, `never` on none.
- Only the SHA-256 of the token is stored. There is no signing secret.
- The session expires `sessions.ttl` after login (default 30 days); it is
  deleted when found expired and a periodic purge removes the rest.
  `last_seen` is updated at most once a minute. Logout deletes the session.
- Each session has its own CSRF token. Requests other than GET, HEAD, OPTIONS
  and TRACE from a logged-in session must send it in the `X-CSRF-Token` header
  or the `csrf_token` form field (constant-time compare), else 403.
- LDAP is consulted at login only, never per request.

HTTP helpers: `Service.SetCookie` / `ClearCookie`, `Service.Middleware` (loads
the session into the context; anonymous requests pass, read it with
`auth.From`), `auth.RequireRole(min)` (401 anonymous, 403 blocked or too low)
and `auth.CSRF`. Chain: `Middleware`, then `CSRF`, then `RequireRole`.

## Login throttling

Five failed attempts per minute per (username, source IP) lock that pair out
for the rest of the window; further attempts are refused without touching LDAP
and without extending the lock. A success clears the counter. The error is a
`*auth.ThrottledError` that also matches `core.ErrInvalidCredentials`. The
table is in memory and forgotten on restart. Failures caused by LDAP being
down do not count. The break-glass admin is throttled like everyone else,
also while LDAP is down: its wrong passwords are "invalid credentials", never
"directory unavailable".

## When LDAP is down

- Existing sessions keep working; nothing on the request path calls LDAP.
- New LDAP logins fail with `core.ErrDirectoryUnavailable` (the UI shows
  "directory unavailable", not "wrong password") and an `error` audit event
  (admins only) is written.
- The local break-glass admin logs in normally, and can fix the LDAP settings.
- A broken filter, wrong base DN, rejected service account or missing bind
  secret behave the same as an unreachable server.

## Audit

Every login attempt writes a `login` event (admins only) (username, source IP,
result, reason `invalid_credentials`, `throttled` or `directory_unavailable`,
method `ldap` or `local`); logout writes `logout`. Passwords are never logged.
