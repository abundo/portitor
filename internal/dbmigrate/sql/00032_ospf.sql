-- SPDX-FileCopyrightText: 2026 The Portitor contributors
-- SPDX-License-Identifier: AGPL-3.0-or-later

-- +goose Up
-- OSPF (FRR's ospfd and ospf6d), per instance and version: 2 (OSPFv2,
-- IPv4) and 3 (OSPFv3, IPv6). Lists are JSON arrays; route maps are
-- referred to by name, interfaces by name.
CREATE TABLE ospf_configs (
    id                    INTEGER PRIMARY KEY AUTOINCREMENT,
    created_at            DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at            DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    instance_id           INTEGER NOT NULL REFERENCES instances(id) ON DELETE CASCADE,
    version               INTEGER NOT NULL DEFAULT 2,
    enabled               BOOLEAN NOT NULL DEFAULT false,
    router_id             TEXT NOT NULL DEFAULT '',
    reference_bandwidth   INTEGER NOT NULL DEFAULT 0,
    log_adjacency_changes BOOLEAN NOT NULL DEFAULT true,
    maximum_paths         INTEGER NOT NULL DEFAULT 0,
    default_originate     BOOLEAN NOT NULL DEFAULT false,
    default_always        BOOLEAN NOT NULL DEFAULT false,
    areas                 TEXT NOT NULL DEFAULT '[]',
    ranges                TEXT NOT NULL DEFAULT '[]',
    summaries             TEXT NOT NULL DEFAULT '[]',
    networks              TEXT NOT NULL DEFAULT '[]',
    redistribute          TEXT NOT NULL DEFAULT '[]',
    UNIQUE (instance_id, version)
);

CREATE TABLE ospf_interfaces (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    created_at     DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at     DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    instance_id    INTEGER NOT NULL REFERENCES instances(id) ON DELETE CASCADE,
    version        INTEGER NOT NULL DEFAULT 2,
    name           TEXT NOT NULL,
    area           TEXT NOT NULL DEFAULT '',
    passive        BOOLEAN NOT NULL DEFAULT false,
    cost           INTEGER NOT NULL DEFAULT 0,
    hello_interval INTEGER NOT NULL DEFAULT 0,
    dead_interval  INTEGER NOT NULL DEFAULT 0,
    priority       INTEGER,
    network_type   TEXT NOT NULL DEFAULT '',
    auth_key_id    INTEGER NOT NULL DEFAULT 0,
    auth_key       TEXT NOT NULL DEFAULT '',
    UNIQUE (instance_id, version, name)
);

-- BGP redistributes OSPF's routes: OSPFv2's into IPv4, OSPFv3's into IPv6.
ALTER TABLE bgp_configs ADD COLUMN redist_ospf_v4 BOOLEAN NOT NULL DEFAULT false;
ALTER TABLE bgp_configs ADD COLUMN redist_ospf_v4_map TEXT NOT NULL DEFAULT '';
ALTER TABLE bgp_configs ADD COLUMN redist_ospf_v6 BOOLEAN NOT NULL DEFAULT false;
ALTER TABLE bgp_configs ADD COLUMN redist_ospf_v6_map TEXT NOT NULL DEFAULT '';

-- +goose Down
ALTER TABLE bgp_configs DROP COLUMN redist_ospf_v6_map;
ALTER TABLE bgp_configs DROP COLUMN redist_ospf_v6;
ALTER TABLE bgp_configs DROP COLUMN redist_ospf_v4_map;
ALTER TABLE bgp_configs DROP COLUMN redist_ospf_v4;
DROP TABLE ospf_interfaces;
DROP TABLE ospf_configs;
