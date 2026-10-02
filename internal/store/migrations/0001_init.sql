-- Initial schema. See docs/data-model.md.
--
-- Conventions: times are INTEGER Unix nanoseconds in UTC, 0 meaning "not
-- set"; booleans are INTEGER 0/1; absent strings are '' (never NULL) so that
-- equality tests and partial indexes stay simple. Identifier sets are stored
-- as names.Set.Key().

CREATE TABLE users (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    username      TEXT    NOT NULL,
    local         INTEGER NOT NULL CHECK (local IN (0, 1)),
    role          TEXT    NOT NULL CHECK (role IN ('normal', 'wildcard_allowed', 'admin')),
    blocked       INTEGER NOT NULL DEFAULT 0 CHECK (blocked IN (0, 1)),
    created_at    INTEGER NOT NULL,
    last_login_at INTEGER NOT NULL DEFAULT 0,
    UNIQUE (username, local)
);

-- An IP grant. prefix is the masked CIDR text; net_start/net_end are the
-- first and last IPv4 address of the prefix as integers so that Match is a
-- range query; bits is the prefix length. owner_user_id is deliberately not
-- a foreign key: a grant's effect never depends on its owner.
CREATE TABLE grants (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    owner_user_id INTEGER NOT NULL,
    prefix        TEXT    NOT NULL,
    net_start     INTEGER NOT NULL,
    net_end       INTEGER NOT NULL,
    bits          INTEGER NOT NULL CHECK (bits BETWEEN 0 AND 32),
    enabled       INTEGER NOT NULL CHECK (enabled IN (0, 1)),
    wildcard      INTEGER NOT NULL CHECK (wildcard IN (0, 1)),
    note          TEXT    NOT NULL DEFAULT '',
    created_at    INTEGER NOT NULL
);
CREATE INDEX grants_range ON grants (net_start, net_end) WHERE enabled = 1;
CREATE INDEX grants_owner ON grants (owner_user_id);

CREATE TABLE sessions (
    token_hash   TEXT    PRIMARY KEY,
    user_id      INTEGER NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    csrf_token   TEXT    NOT NULL,
    source_ip    TEXT    NOT NULL DEFAULT '',
    created_at   INTEGER NOT NULL,
    expires_at   INTEGER NOT NULL,
    last_seen_at INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX sessions_user ON sessions (user_id);
CREATE INDEX sessions_expires ON sessions (expires_at);

CREATE TABLE acme_accounts (
    id         TEXT    PRIMARY KEY,
    thumbprint TEXT    NOT NULL UNIQUE,
    jwk        BLOB    NOT NULL,
    status     TEXT    NOT NULL CHECK (status IN ('valid', 'deactivated')),
    contact    TEXT    NOT NULL DEFAULT '[]', -- JSON array of URLs
    created_at INTEGER NOT NULL
);

-- Certificates the broker obtained upstream. Rows are never deleted;
-- chain_pem is NULL for direct-mode certificates and after DropChains.
-- replaces_id / replaced_by_id are not foreign keys so that a stale or
-- foreign reference never blocks issuance.
CREATE TABLE certificates (
    id             TEXT    PRIMARY KEY,
    order_id       TEXT    NOT NULL,
    mode           TEXT    NOT NULL CHECK (mode IN ('acme', 'direct')),
    set_key        TEXT    NOT NULL,
    provider       TEXT    NOT NULL,
    account_url    TEXT    NOT NULL DEFAULT '',
    serial         TEXT    NOT NULL DEFAULT '',
    ari_cert_id    TEXT    NOT NULL DEFAULT '',
    not_before     INTEGER NOT NULL,
    not_after      INTEGER NOT NULL,
    issued_at      INTEGER NOT NULL,
    chain_pem      BLOB,
    replaces_id    TEXT    NOT NULL DEFAULT '',
    replaced_by_id TEXT    NOT NULL DEFAULT ''
);
CREATE UNIQUE INDEX certificates_ari ON certificates (ari_cert_id) WHERE ari_cert_id <> '';
CREATE INDEX certificates_lineage ON certificates (set_key, provider, not_before);
CREATE INDEX certificates_not_after ON certificates (not_after);

-- Broker orders: downstream ACME orders and direct-mode issuance jobs.
-- account_id is not a foreign key (direct orders have none, and accounts are
-- protocol state only). certificate_id is set only by Complete, in the same
-- transaction that inserts the certificate.
CREATE TABLE orders (
    id                  TEXT    PRIMARY KEY,
    mode                TEXT    NOT NULL CHECK (mode IN ('acme', 'direct')),
    account_id          TEXT    NOT NULL DEFAULT '',
    set_key             TEXT    NOT NULL,
    replaces            TEXT    NOT NULL DEFAULT '',
    source_ip           TEXT    NOT NULL DEFAULT '',
    grant_id            INTEGER NOT NULL DEFAULT 0,
    status              TEXT    NOT NULL CHECK (status IN ('ready', 'processing', 'valid', 'invalid')),
    prep                TEXT    NOT NULL CHECK (prep IN ('intent', 'preparing', 'prepared', 'failed')),
    class               INTEGER NOT NULL DEFAULT 0,
    ari_qualified       INTEGER NOT NULL DEFAULT 0 CHECK (ari_qualified IN (0, 1)),
    provider            TEXT    NOT NULL,
    upstream_order_url  TEXT    NOT NULL DEFAULT '',
    upstream_replaces   TEXT    NOT NULL DEFAULT '',
    upstream_expires_at INTEGER NOT NULL DEFAULT 0,
    adopted_by_order_id TEXT    NOT NULL DEFAULT '',
    csr_hash            TEXT    NOT NULL DEFAULT '',
    csr_der             BLOB,
    certificate_id      TEXT    REFERENCES certificates (id),
    error               TEXT    NOT NULL DEFAULT '', -- JSON problem document
    created_at          INTEGER NOT NULL,
    expires_at          INTEGER NOT NULL,
    updated_at          INTEGER NOT NULL,
    -- A CSR is kept only while the order is not terminal.
    CHECK (csr_der IS NULL OR status IN ('ready', 'processing')),
    -- A valid order always points at its certificate.
    CHECK (status <> 'valid' OR certificate_id IS NOT NULL)
);
-- One upstream order serves at most one order that still owns it: an order
-- gives its upstream order away only by being adopted.
CREATE UNIQUE INDEX orders_upstream_owner ON orders (upstream_order_url)
    WHERE upstream_order_url <> '' AND adopted_by_order_id = '';
CREATE INDEX orders_open ON orders (account_id, set_key, status, created_at);
CREATE INDEX orders_adoptable ON orders (provider, set_key, created_at)
    WHERE status = 'invalid' AND prep = 'prepared' AND csr_hash = '' AND adopted_by_order_id = '';
CREATE INDEX orders_active ON orders (created_at) WHERE status IN ('ready', 'processing');
CREATE INDEX orders_created ON orders (created_at);
CREATE INDEX orders_updated ON orders (updated_at) WHERE status IN ('valid', 'invalid');
CREATE INDEX orders_adopted_by ON orders (adopted_by_order_id) WHERE adopted_by_order_id <> '';

CREATE TABLE lineages (
    key               TEXT    PRIMARY KEY,
    last_request_at   INTEGER NOT NULL DEFAULT 0,
    observed_interval INTEGER NOT NULL DEFAULT 0, -- nanoseconds
    samples           INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE challenges (
    id          TEXT    PRIMARY KEY,
    zone_id     TEXT    NOT NULL,
    record_name TEXT    NOT NULL,
    value       TEXT    NOT NULL,
    owner       TEXT    NOT NULL,
    state       TEXT    NOT NULL CHECK (state IN ('pending', 'presenting', 'waiting_dns', 'ready', 'cleaning', 'done', 'failed')),
    error       TEXT    NOT NULL DEFAULT '',
    created_at  INTEGER NOT NULL,
    updated_at  INTEGER NOT NULL
);
CREATE INDEX challenges_active ON challenges (created_at) WHERE state NOT IN ('done', 'failed');
CREATE INDEX challenges_record ON challenges (zone_id, record_name) WHERE state NOT IN ('done', 'failed');
CREATE INDEX challenges_owner ON challenges (owner, created_at);
CREATE INDEX challenges_finished ON challenges (updated_at) WHERE state IN ('done', 'failed');

-- Direct-cache metadata. Keys and chains live on disk only.
CREATE TABLE direct_entries (
    identifier        TEXT    PRIMARY KEY,
    generation        INTEGER NOT NULL DEFAULT 0,
    certificate_id    TEXT    NOT NULL DEFAULT '',
    provider          TEXT    NOT NULL DEFAULT '',
    not_before        INTEGER NOT NULL DEFAULT 0,
    not_after         INTEGER NOT NULL DEFAULT 0,
    renew_at          INTEGER NOT NULL DEFAULT 0,
    next_ari_check_at INTEGER NOT NULL DEFAULT 0,
    last_fetch_at     INTEGER NOT NULL DEFAULT 0,
    last_fetch_ip     TEXT    NOT NULL DEFAULT '',
    last_attempt_at   INTEGER NOT NULL DEFAULT 0,
    last_error        TEXT    NOT NULL DEFAULT '',
    failures          INTEGER NOT NULL DEFAULT 0,
    created_at        INTEGER NOT NULL,
    updated_at        INTEGER NOT NULL
);

CREATE TABLE provider_states (
    name        TEXT    PRIMARY KEY,
    health      TEXT    NOT NULL,
    retry_after INTEGER NOT NULL DEFAULT 0,
    last_error  TEXT    NOT NULL DEFAULT '',
    failures    INTEGER NOT NULL DEFAULT 0,
    updated_at  INTEGER NOT NULL
);

-- Scheduler budget events (sliding windows). Reserved events are held by an
-- admitted request; committed ones count until they leave the window.
CREATE TABLE budget_events (
    id       INTEGER PRIMARY KEY AUTOINCREMENT,
    ref      TEXT    NOT NULL,
    provider TEXT    NOT NULL,
    kind     TEXT    NOT NULL CHECK (kind IN ('new_order', 'cert_domain', 'cert_set')),
    key      TEXT    NOT NULL DEFAULT '',
    at       INTEGER NOT NULL,
    state    TEXT    NOT NULL CHECK (state IN ('reserved', 'committed')),
    renewal  INTEGER NOT NULL DEFAULT 0 CHECK (renewal IN (0, 1))
);
CREATE INDEX budget_events_ref ON budget_events (ref);
CREATE INDEX budget_events_at ON budget_events (at);
CREATE INDEX budget_events_reserved ON budget_events (id) WHERE state = 'reserved';
