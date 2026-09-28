-- SPDX-FileCopyrightText: 2026 The Portitor contributors
-- SPDX-License-Identifier: AGPL-3.0-or-later

-- +goose Up
-- SQLite. Ids are AUTOINCREMENT so a deleted row's id is never reused
-- (accept rules mark connections with the rule id). JSON lists are TEXT;
-- times are DATETIME so the driver scans them into time.Time. Foreign keys
-- are enforced only with PRAGMA foreign_keys=ON, which ConnectDB sets.

CREATE TABLE users (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    created_at    DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at    DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    username      TEXT NOT NULL UNIQUE,
    full_name     TEXT NOT NULL DEFAULT '',
    email         TEXT NOT NULL DEFAULT '',
    password_hash TEXT NOT NULL,
    token_version INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE settings (
    id                INTEGER PRIMARY KEY,
    agent_url         TEXT NOT NULL DEFAULT '',
    agent_token       TEXT NOT NULL DEFAULT '',
    agent_fingerprint TEXT NOT NULL DEFAULT '',
    confirm_timeout   INTEGER NOT NULL DEFAULT 120,
    wg_endpoint_host  TEXT NOT NULL DEFAULT '',
    generation        INTEGER NOT NULL DEFAULT 0,
    updated_at        DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);
INSERT INTO settings (id) VALUES (1);

CREATE TABLE instances (
    id                     INTEGER PRIMARY KEY AUTOINCREMENT,
    created_at             DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at             DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    name                   TEXT NOT NULL UNIQUE,
    description            TEXT NOT NULL DEFAULT '',
    is_default             BOOLEAN NOT NULL DEFAULT false,
    dns_enabled            BOOLEAN NOT NULL DEFAULT false,
    dns_forwarders         TEXT NOT NULL DEFAULT '[]',
    dns_forward_from_dhcp  BOOLEAN NOT NULL DEFAULT false,
    -- How BIND uses the forwarders: first (fall back to the root servers),
    -- only, or off (resolve from the root servers).
    dns_forward_mode       TEXT NOT NULL DEFAULT 'first',
    dns_allow_recursion    TEXT NOT NULL DEFAULT '[]',
    dhcp_enabled           BOOLEAN NOT NULL DEFAULT false,
    dhcp_domain_name       TEXT NOT NULL DEFAULT '',
    dhcp_lease_time        INTEGER NOT NULL DEFAULT 86400,
    -- The filter chains (input, forward, output) whose policy drops and
    -- invalid packet drops are logged, and the auto input rules (by
    -- service) whose matches are.
    log_drops              TEXT NOT NULL DEFAULT '[]',
    log_invalid            TEXT NOT NULL DEFAULT '[]',
    log_auto               TEXT NOT NULL DEFAULT '[]'
);
CREATE UNIQUE INDEX instances_one_default ON instances (is_default) WHERE is_default;

-- Named groups of zero or more interfaces of an instance. Rules and NAT
-- rules list interfaces and interface zones by name. An interface may be
-- in several zones.
CREATE TABLE interface_zones (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    created_at   DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at   DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    instance_id  INTEGER NOT NULL REFERENCES instances(id) ON DELETE CASCADE,
    name         TEXT NOT NULL,
    description  TEXT NOT NULL DEFAULT '',
    interfaces   TEXT NOT NULL DEFAULT '[]',
    UNIQUE (instance_id, name)
);

CREATE TABLE interfaces (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    created_at      DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at      DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    instance_id     INTEGER NOT NULL REFERENCES instances(id) ON DELETE CASCADE,
    name            TEXT NOT NULL,
    kind            TEXT NOT NULL DEFAULT 'physical',
    description     TEXT NOT NULL DEFAULT '',
    enabled         BOOLEAN NOT NULL DEFAULT true,
    parent          TEXT NOT NULL DEFAULT '',
    vlan_id         INTEGER NOT NULL DEFAULT 0,
    members         TEXT NOT NULL DEFAULT '[]',
    mtu             INTEGER NOT NULL DEFAULT 0,
    ipv4_mode       TEXT NOT NULL DEFAULT 'static',
    ipv6_accept_ra  BOOLEAN NOT NULL DEFAULT false,
    dns_listen      BOOLEAN NOT NULL DEFAULT false,
    wg_private_key  TEXT NOT NULL DEFAULT '',
    wg_public_key   TEXT NOT NULL DEFAULT '',
    wg_listen_port  INTEGER NOT NULL DEFAULT 0,
    -- Defaults for generated WireGuard client configs: the public endpoint
    -- (host:port) and the client's persistent keepalive.
    wg_endpoint     TEXT NOT NULL DEFAULT '',
    wg_keepalive    INTEGER NOT NULL DEFAULT 25,
    UNIQUE (instance_id, name)
);

CREATE TABLE wg_peers (
    id                 INTEGER PRIMARY KEY AUTOINCREMENT,
    created_at         DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at         DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    interface_id       INTEGER NOT NULL REFERENCES interfaces(id) ON DELETE CASCADE,
    name               TEXT NOT NULL,
    description        TEXT NOT NULL DEFAULT '',
    enabled            BOOLEAN NOT NULL DEFAULT true,
    public_key         TEXT NOT NULL,
    preshared_key      TEXT NOT NULL DEFAULT '',
    endpoint           TEXT NOT NULL DEFAULT '',
    allowed_ips        TEXT NOT NULL DEFAULT '[]',
    keepalive          INTEGER NOT NULL DEFAULT 0,
    client_private_key TEXT NOT NULL DEFAULT '',
    UNIQUE (interface_id, public_key)
);

CREATE TABLE links (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    created_at    DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at    DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    name          TEXT NOT NULL UNIQUE,
    description   TEXT NOT NULL DEFAULT '',
    instance_a_id INTEGER NOT NULL REFERENCES instances(id) ON DELETE CASCADE,
    interface_a   TEXT NOT NULL,
    addresses_a   TEXT NOT NULL DEFAULT '[]',
    instance_b_id INTEGER NOT NULL REFERENCES instances(id) ON DELETE CASCADE,
    interface_b   TEXT NOT NULL,
    addresses_b   TEXT NOT NULL DEFAULT '[]'
);

CREATE TABLE routes (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    created_at   DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at   DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    instance_id  INTEGER NOT NULL REFERENCES instances(id) ON DELETE CASCADE,
    destination  TEXT NOT NULL,
    gateway      TEXT NOT NULL DEFAULT '',
    interface_id INTEGER REFERENCES interfaces(id) ON DELETE CASCADE,
    metric       INTEGER NOT NULL DEFAULT 0,
    enabled      BOOLEAN NOT NULL DEFAULT true,
    description  TEXT NOT NULL DEFAULT ''
);

CREATE TABLE rules (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    created_at     DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at     DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    instance_id    INTEGER NOT NULL REFERENCES instances(id) ON DELETE CASCADE,
    position       INTEGER NOT NULL DEFAULT 0,
    -- '' for a rule, 'comment' for a comment row (text in description).
    kind           TEXT NOT NULL DEFAULT '',
    chain          TEXT NOT NULL,
    in_interfaces  TEXT NOT NULL DEFAULT '[]',
    out_interfaces TEXT NOT NULL DEFAULT '[]',
    family         TEXT NOT NULL DEFAULT '',
    protocol       TEXT NOT NULL DEFAULT '',
    src_addrs      TEXT NOT NULL DEFAULT '[]',
    dst_addrs      TEXT NOT NULL DEFAULT '[]',
    dst_ports      TEXT NOT NULL DEFAULT '',
    action         TEXT NOT NULL DEFAULT 'accept',
    log            BOOLEAN NOT NULL DEFAULT false,
    enabled        BOOLEAN NOT NULL DEFAULT true,
    description    TEXT NOT NULL DEFAULT ''
);
CREATE INDEX rules_instance_position ON rules (instance_id, position);

CREATE TABLE nat_rules (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    created_at     DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at     DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    instance_id    INTEGER NOT NULL REFERENCES instances(id) ON DELETE CASCADE,
    position       INTEGER NOT NULL DEFAULT 0,
    kind           TEXT NOT NULL,
    in_interfaces  TEXT NOT NULL DEFAULT '[]',
    out_interfaces TEXT NOT NULL DEFAULT '[]',
    protocol       TEXT NOT NULL DEFAULT '',
    src_addrs      TEXT NOT NULL DEFAULT '[]',
    dst_addrs      TEXT NOT NULL DEFAULT '[]',
    dst_ports      TEXT NOT NULL DEFAULT '',
    to_addr        TEXT NOT NULL DEFAULT '',
    to_port        INTEGER NOT NULL DEFAULT 0,
    enabled        BOOLEAN NOT NULL DEFAULT true,
    description    TEXT NOT NULL DEFAULT ''
);

CREATE TABLE ipam_prefixes (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    created_at       DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at       DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    instance_id      INTEGER NOT NULL REFERENCES instances(id) ON DELETE CASCADE,
    prefix           TEXT NOT NULL,
    description      TEXT NOT NULL DEFAULT '',
    dhcp_enabled     BOOLEAN NOT NULL DEFAULT false,
    dhcp_range_start TEXT NOT NULL DEFAULT '',
    dhcp_range_end   TEXT NOT NULL DEFAULT '',
    dhcp_gateway     TEXT NOT NULL DEFAULT '',
    dhcp_dns_servers TEXT NOT NULL DEFAULT '[]',
    -- IPv6 router advertisements; ra_slaac sets the autonomous flag
    -- (clients pick their own address, /64 only).
    ra_enabled       BOOLEAN NOT NULL DEFAULT false,
    ra_slaac         BOOLEAN NOT NULL DEFAULT false,
    UNIQUE (instance_id, prefix)
);

CREATE TABLE ipam_addresses (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    created_at   DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at   DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    instance_id  INTEGER NOT NULL REFERENCES instances(id) ON DELETE CASCADE,
    address      TEXT NOT NULL,
    interface_id INTEGER REFERENCES interfaces(id) ON DELETE SET NULL,
    dns_name     TEXT NOT NULL DEFAULT '',
    mac          TEXT NOT NULL DEFAULT '',
    description  TEXT NOT NULL DEFAULT '',
    UNIQUE (instance_id, address)
);

-- DNS templates, shared by all instances: a zone's template gives it its
-- SOA (from an SOA template), default TTL, apex NS records and optionally a
-- DNSSEC policy. A zone without a template gets a built-in SOA/NS pointing
-- at localhost.
CREATE TABLE dns_soa_templates (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    name       TEXT NOT NULL UNIQUE,
    mname      TEXT NOT NULL,
    rname      TEXT NOT NULL,
    refresh    INTEGER NOT NULL DEFAULT 86400,
    retry      INTEGER NOT NULL DEFAULT 7200,
    expire     INTEGER NOT NULL DEFAULT 3600000,
    minimum    INTEGER NOT NULL DEFAULT 3600
);

CREATE TABLE dns_dnssec_policies (
    id                         INTEGER PRIMARY KEY AUTOINCREMENT,
    created_at                 DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at                 DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    name                       TEXT NOT NULL UNIQUE,
    ksk_lifetime               TEXT NOT NULL DEFAULT '',
    ksk_algorithm              TEXT NOT NULL,
    zsk_lifetime               TEXT NOT NULL DEFAULT '',
    zsk_algorithm              TEXT NOT NULL,
    purge_keys                 TEXT NOT NULL DEFAULT '',
    signatures_validity        TEXT NOT NULL DEFAULT '',
    signatures_validity_dnskey TEXT NOT NULL DEFAULT '',
    signatures_refresh         TEXT NOT NULL DEFAULT ''
);

CREATE TABLE dns_templates (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    created_at       DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at       DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    name             TEXT NOT NULL UNIQUE,
    soa_template_id  INTEGER NOT NULL REFERENCES dns_soa_templates(id) ON DELETE RESTRICT,
    default_ttl      INTEGER NOT NULL DEFAULT 3600,
    dnssec_policy_id INTEGER REFERENCES dns_dnssec_policies(id) ON DELETE RESTRICT,
    nameservers      TEXT NOT NULL DEFAULT '[]',
    description      TEXT NOT NULL DEFAULT ''
);

CREATE TABLE dns_zones (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    created_at      DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at      DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    instance_id     INTEGER NOT NULL REFERENCES instances(id) ON DELETE CASCADE,
    name            TEXT NOT NULL,
    type            TEXT NOT NULL DEFAULT 'forward',
    description     TEXT NOT NULL DEFAULT '',
    dns_template_id INTEGER REFERENCES dns_templates(id) ON DELETE RESTRICT,
    UNIQUE (instance_id, name)
);

-- Records keep the order they are edited in (the zone editor is a grid).
-- Rows of type COMMENT and $DOMAIN are editor-only: comments are dropped
-- and $DOMAIN makes the names below it relative to a subdomain when the
-- document is built.
CREATE TABLE dns_records (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    created_at  DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at  DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    zone_id     INTEGER NOT NULL REFERENCES dns_zones(id) ON DELETE CASCADE,
    rank        INTEGER NOT NULL DEFAULT 0,
    name        TEXT NOT NULL,
    ttl         INTEGER NOT NULL DEFAULT 0,
    type        TEXT NOT NULL,
    value       TEXT NOT NULL,
    mac         TEXT NOT NULL DEFAULT '',
    description TEXT NOT NULL DEFAULT ''
);

CREATE TABLE deployments (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    generation INTEGER NOT NULL,
    username   TEXT NOT NULL DEFAULT '',
    status     TEXT NOT NULL,
    message    TEXT NOT NULL DEFAULT '',
    document   TEXT NOT NULL,
    -- Hash of the full (unredacted) document, so the GUI can tell whether
    -- the database has changes that are not deployed.
    doc_hash   TEXT NOT NULL DEFAULT '',
    log        TEXT NOT NULL DEFAULT ''
);
CREATE INDEX deployments_generation ON deployments (generation);

-- Named hosts and prefixes, usable by name wherever an address list is
-- entered (rules, NAT, routes, DNS, WireGuard, DHCP). A host is an object
-- whose entries are all single addresses.
CREATE TABLE address_objects (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    created_at  DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at  DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    name        TEXT NOT NULL UNIQUE,
    addresses   TEXT NOT NULL DEFAULT '[]',
    description TEXT NOT NULL DEFAULT ''
);

-- Physical interfaces the agent has reported. A new one is imported into
-- the default instance once; one the user deleted is not imported again.
CREATE TABLE known_interfaces (
    name        TEXT PRIMARY KEY,
    created_at  DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- Dynamic DNS clients: RFC 2136 updates of records on an external
-- nameserver, following an interface's addresses. Deleting an interface
-- a client uses is refused (NO ACTION, checked at the end of the
-- statement, so deleting the whole instance still works).
CREATE TABLE dyndns_clients (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    created_at      DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at      DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    instance_id     INTEGER NOT NULL REFERENCES instances(id) ON DELETE CASCADE,
    name            TEXT NOT NULL,
    description     TEXT NOT NULL DEFAULT '',
    enabled         BOOLEAN NOT NULL DEFAULT true,
    interface_id    INTEGER NOT NULL REFERENCES interfaces(id),
    server          TEXT NOT NULL,
    zone            TEXT NOT NULL,
    tsig_name       TEXT NOT NULL DEFAULT '',
    tsig_algorithm  TEXT NOT NULL DEFAULT '',
    tsig_secret     TEXT NOT NULL DEFAULT '',
    retry_interval  INTEGER NOT NULL DEFAULT 0,
    verify_interval INTEGER NOT NULL DEFAULT 0,
    UNIQUE (instance_id, name)
);

CREATE TABLE dyndns_records (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    created_at  DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at  DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    client_id   INTEGER NOT NULL REFERENCES dyndns_clients(id) ON DELETE CASCADE,
    name        TEXT NOT NULL,
    type        TEXT NOT NULL,
    ttl         INTEGER NOT NULL DEFAULT 0,
    value       TEXT NOT NULL DEFAULT '',
    description TEXT NOT NULL DEFAULT ''
);

-- IP lists the agent downloads (CrowdSec decisions, or a plain-text list
-- such as a CrowdSec blocklist integration). Rules refer to one as
-- "@name" in their address lists.
CREATE TABLE ip_lists (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    created_at  DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at  DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    name        TEXT NOT NULL UNIQUE,
    description TEXT NOT NULL DEFAULT '',
    source      TEXT NOT NULL,
    url         TEXT NOT NULL,
    username    TEXT NOT NULL DEFAULT '',
    password    TEXT NOT NULL DEFAULT '',
    api_key     TEXT NOT NULL DEFAULT ''
);

-- Tasks the agent runs on a cron schedule: download an IP list, or run a
-- command as the agent's console user. Deleting a list a task downloads
-- is refused.
CREATE TABLE tasks (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    created_at  DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at  DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    name        TEXT NOT NULL UNIQUE,
    description TEXT NOT NULL DEFAULT '',
    enabled     BOOLEAN NOT NULL DEFAULT true,
    schedule    TEXT NOT NULL,
    kind        TEXT NOT NULL,
    ip_list_id  INTEGER REFERENCES ip_lists(id),
    command     TEXT NOT NULL DEFAULT '',
    timeout     INTEGER NOT NULL DEFAULT 0
);

-- +goose Down
DROP TABLE tasks;
DROP TABLE ip_lists;
DROP TABLE dyndns_records;
DROP TABLE dyndns_clients;
DROP TABLE known_interfaces;
DROP TABLE address_objects;
DROP TABLE deployments;
DROP TABLE dns_records;
DROP TABLE dns_zones;
DROP TABLE dns_templates;
DROP TABLE dns_dnssec_policies;
DROP TABLE dns_soa_templates;
DROP TABLE ipam_addresses;
DROP TABLE ipam_prefixes;
DROP TABLE nat_rules;
DROP TABLE rules;
DROP TABLE routes;
DROP TABLE links;
DROP TABLE wg_peers;
DROP TABLE interfaces;
DROP TABLE interface_zones;
DROP TABLE instances;
DROP TABLE settings;
DROP TABLE users;
