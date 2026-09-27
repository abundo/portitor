-- SPDX-FileCopyrightText: 2026 The Portitor contributors
-- SPDX-License-Identifier: AGPL-3.0-or-later

-- +goose Up
CREATE TABLE users (
    id            BIGSERIAL PRIMARY KEY,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    username      TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    token_version INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE settings (
    id                BIGINT PRIMARY KEY,
    agent_url         TEXT NOT NULL DEFAULT '',
    agent_token       TEXT NOT NULL DEFAULT '',
    agent_fingerprint TEXT NOT NULL DEFAULT '',
    confirm_timeout   INTEGER NOT NULL DEFAULT 120,
    wg_endpoint_host  TEXT NOT NULL DEFAULT '',
    generation        BIGINT NOT NULL DEFAULT 0,
    updated_at        TIMESTAMPTZ NOT NULL DEFAULT now()
);
INSERT INTO settings (id) VALUES (1);

CREATE TABLE instances (
    id                     BIGSERIAL PRIMARY KEY,
    created_at             TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at             TIMESTAMPTZ NOT NULL DEFAULT now(),
    name                   TEXT NOT NULL UNIQUE,
    description            TEXT NOT NULL DEFAULT '',
    is_default             BOOLEAN NOT NULL DEFAULT false,
    dns_enabled            BOOLEAN NOT NULL DEFAULT false,
    dns_forwarders         JSONB NOT NULL DEFAULT '[]',
    dns_forward_from_dhcp  BOOLEAN NOT NULL DEFAULT false,
    dns_allow_recursion    JSONB NOT NULL DEFAULT '[]',
    dhcp_enabled           BOOLEAN NOT NULL DEFAULT false,
    dhcp_domain_name       TEXT NOT NULL DEFAULT '',
    dhcp_lease_time        INTEGER NOT NULL DEFAULT 86400
);
CREATE UNIQUE INDEX instances_one_default ON instances (is_default) WHERE is_default;

CREATE TABLE zones (
    id           BIGSERIAL PRIMARY KEY,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    instance_id  BIGINT NOT NULL REFERENCES instances(id) ON DELETE CASCADE,
    name         TEXT NOT NULL,
    description  TEXT NOT NULL DEFAULT '',
    input_policy TEXT NOT NULL DEFAULT 'drop',
    masquerade   BOOLEAN NOT NULL DEFAULT false,
    UNIQUE (instance_id, name)
);

CREATE TABLE interfaces (
    id              BIGSERIAL PRIMARY KEY,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    instance_id     BIGINT NOT NULL REFERENCES instances(id) ON DELETE CASCADE,
    name            TEXT NOT NULL,
    kind            TEXT NOT NULL DEFAULT 'physical',
    description     TEXT NOT NULL DEFAULT '',
    enabled         BOOLEAN NOT NULL DEFAULT true,
    parent          TEXT NOT NULL DEFAULT '',
    vlan_id         INTEGER NOT NULL DEFAULT 0,
    members         JSONB NOT NULL DEFAULT '[]',
    mtu             INTEGER NOT NULL DEFAULT 0,
    zone_id         BIGINT REFERENCES zones(id) ON DELETE SET NULL,
    ipv4_mode       TEXT NOT NULL DEFAULT 'static',
    ipv6_accept_ra  BOOLEAN NOT NULL DEFAULT false,
    dns_listen      BOOLEAN NOT NULL DEFAULT false,
    wg_private_key  TEXT NOT NULL DEFAULT '',
    wg_public_key   TEXT NOT NULL DEFAULT '',
    wg_listen_port  INTEGER NOT NULL DEFAULT 0,
    UNIQUE (instance_id, name)
);

CREATE TABLE wg_peers (
    id                 BIGSERIAL PRIMARY KEY,
    created_at         TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at         TIMESTAMPTZ NOT NULL DEFAULT now(),
    interface_id       BIGINT NOT NULL REFERENCES interfaces(id) ON DELETE CASCADE,
    name               TEXT NOT NULL,
    description        TEXT NOT NULL DEFAULT '',
    enabled            BOOLEAN NOT NULL DEFAULT true,
    public_key         TEXT NOT NULL,
    preshared_key      TEXT NOT NULL DEFAULT '',
    endpoint           TEXT NOT NULL DEFAULT '',
    allowed_ips        JSONB NOT NULL DEFAULT '[]',
    keepalive          INTEGER NOT NULL DEFAULT 0,
    client_private_key TEXT NOT NULL DEFAULT '',
    UNIQUE (interface_id, public_key)
);

CREATE TABLE links (
    id            BIGSERIAL PRIMARY KEY,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    name          TEXT NOT NULL UNIQUE,
    description   TEXT NOT NULL DEFAULT '',
    instance_a_id BIGINT NOT NULL REFERENCES instances(id) ON DELETE CASCADE,
    interface_a   TEXT NOT NULL,
    zone_a_id     BIGINT REFERENCES zones(id) ON DELETE SET NULL,
    addresses_a   JSONB NOT NULL DEFAULT '[]',
    instance_b_id BIGINT NOT NULL REFERENCES instances(id) ON DELETE CASCADE,
    interface_b   TEXT NOT NULL,
    zone_b_id     BIGINT REFERENCES zones(id) ON DELETE SET NULL,
    addresses_b   JSONB NOT NULL DEFAULT '[]'
);

CREATE TABLE routes (
    id           BIGSERIAL PRIMARY KEY,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    instance_id  BIGINT NOT NULL REFERENCES instances(id) ON DELETE CASCADE,
    destination  TEXT NOT NULL,
    gateway      TEXT NOT NULL DEFAULT '',
    interface_id BIGINT REFERENCES interfaces(id) ON DELETE CASCADE,
    metric       INTEGER NOT NULL DEFAULT 0,
    enabled      BOOLEAN NOT NULL DEFAULT true,
    description  TEXT NOT NULL DEFAULT ''
);

CREATE TABLE rules (
    id          BIGSERIAL PRIMARY KEY,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    instance_id BIGINT NOT NULL REFERENCES instances(id) ON DELETE CASCADE,
    position    INTEGER NOT NULL DEFAULT 0,
    chain       TEXT NOT NULL,
    src_zone_id BIGINT REFERENCES zones(id) ON DELETE CASCADE,
    dst_zone_id BIGINT REFERENCES zones(id) ON DELETE CASCADE,
    family      TEXT NOT NULL DEFAULT '',
    protocol    TEXT NOT NULL DEFAULT '',
    src_addrs   JSONB NOT NULL DEFAULT '[]',
    dst_addrs   JSONB NOT NULL DEFAULT '[]',
    dst_ports   TEXT NOT NULL DEFAULT '',
    action      TEXT NOT NULL DEFAULT 'accept',
    log         BOOLEAN NOT NULL DEFAULT false,
    enabled     BOOLEAN NOT NULL DEFAULT true,
    description TEXT NOT NULL DEFAULT ''
);
CREATE INDEX rules_instance_position ON rules (instance_id, position);

CREATE TABLE nat_rules (
    id          BIGSERIAL PRIMARY KEY,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    instance_id BIGINT NOT NULL REFERENCES instances(id) ON DELETE CASCADE,
    position    INTEGER NOT NULL DEFAULT 0,
    kind        TEXT NOT NULL,
    in_zone_id  BIGINT REFERENCES zones(id) ON DELETE CASCADE,
    out_zone_id BIGINT REFERENCES zones(id) ON DELETE CASCADE,
    protocol    TEXT NOT NULL DEFAULT '',
    src_addrs   JSONB NOT NULL DEFAULT '[]',
    dst_addrs   JSONB NOT NULL DEFAULT '[]',
    dst_ports   TEXT NOT NULL DEFAULT '',
    to_addr     TEXT NOT NULL DEFAULT '',
    to_port     INTEGER NOT NULL DEFAULT 0,
    enabled     BOOLEAN NOT NULL DEFAULT true,
    description TEXT NOT NULL DEFAULT ''
);

CREATE TABLE ipam_prefixes (
    id               BIGSERIAL PRIMARY KEY,
    created_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    instance_id      BIGINT NOT NULL REFERENCES instances(id) ON DELETE CASCADE,
    prefix           TEXT NOT NULL,
    description      TEXT NOT NULL DEFAULT '',
    dhcp_enabled     BOOLEAN NOT NULL DEFAULT false,
    dhcp_range_start TEXT NOT NULL DEFAULT '',
    dhcp_range_end   TEXT NOT NULL DEFAULT '',
    dhcp_gateway     TEXT NOT NULL DEFAULT '',
    dhcp_dns_servers JSONB NOT NULL DEFAULT '[]',
    UNIQUE (instance_id, prefix)
);

CREATE TABLE ipam_addresses (
    id           BIGSERIAL PRIMARY KEY,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    instance_id  BIGINT NOT NULL REFERENCES instances(id) ON DELETE CASCADE,
    address      TEXT NOT NULL,
    interface_id BIGINT REFERENCES interfaces(id) ON DELETE SET NULL,
    dns_name     TEXT NOT NULL DEFAULT '',
    mac          TEXT NOT NULL DEFAULT '',
    description  TEXT NOT NULL DEFAULT '',
    UNIQUE (instance_id, address)
);

CREATE TABLE dns_zones (
    id          BIGSERIAL PRIMARY KEY,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    instance_id BIGINT NOT NULL REFERENCES instances(id) ON DELETE CASCADE,
    name        TEXT NOT NULL,
    type        TEXT NOT NULL DEFAULT 'forward',
    description TEXT NOT NULL DEFAULT '',
    UNIQUE (instance_id, name)
);

CREATE TABLE dns_records (
    id          BIGSERIAL PRIMARY KEY,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    zone_id     BIGINT NOT NULL REFERENCES dns_zones(id) ON DELETE CASCADE,
    name        TEXT NOT NULL,
    ttl         BIGINT NOT NULL DEFAULT 0,
    type        TEXT NOT NULL,
    value       TEXT NOT NULL,
    mac         TEXT NOT NULL DEFAULT '',
    description TEXT NOT NULL DEFAULT ''
);

CREATE TABLE deployments (
    id         BIGSERIAL PRIMARY KEY,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    generation BIGINT NOT NULL,
    username   TEXT NOT NULL DEFAULT '',
    status     TEXT NOT NULL,
    message    TEXT NOT NULL DEFAULT '',
    document   JSONB NOT NULL,
    log        TEXT NOT NULL DEFAULT ''
);
CREATE INDEX deployments_generation ON deployments (generation);

-- +goose Down
DROP TABLE deployments;
DROP TABLE dns_records;
DROP TABLE dns_zones;
DROP TABLE ipam_addresses;
DROP TABLE ipam_prefixes;
DROP TABLE nat_rules;
DROP TABLE rules;
DROP TABLE routes;
DROP TABLE links;
DROP TABLE wg_peers;
DROP TABLE interfaces;
DROP TABLE zones;
DROP TABLE instances;
DROP TABLE settings;
DROP TABLE users;
