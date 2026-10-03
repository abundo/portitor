-- SPDX-FileCopyrightText: 2026 The Portitor contributors
-- SPDX-License-Identifier: AGPL-3.0-or-later

-- +goose Up
-- Routing policy objects (Network > Routing > Routing objects) and BGP
-- (FRR), per instance. Entries are JSON arrays; references between them
-- are by name.
CREATE TABLE route_prefix_lists (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    created_at  DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at  DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    instance_id INTEGER NOT NULL REFERENCES instances(id) ON DELETE CASCADE,
    name        TEXT NOT NULL,
    family      TEXT NOT NULL DEFAULT 'ipv4',
    description TEXT NOT NULL DEFAULT '',
    entries     TEXT NOT NULL DEFAULT '[]',
    UNIQUE (instance_id, name)
);

CREATE TABLE route_as_path_lists (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    created_at  DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at  DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    instance_id INTEGER NOT NULL REFERENCES instances(id) ON DELETE CASCADE,
    name        TEXT NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    entries     TEXT NOT NULL DEFAULT '[]',
    UNIQUE (instance_id, name)
);

CREATE TABLE route_community_lists (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    created_at  DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at  DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    instance_id INTEGER NOT NULL REFERENCES instances(id) ON DELETE CASCADE,
    name        TEXT NOT NULL,
    kind        TEXT NOT NULL DEFAULT 'standard',
    description TEXT NOT NULL DEFAULT '',
    entries     TEXT NOT NULL DEFAULT '[]',
    UNIQUE (instance_id, name)
);

CREATE TABLE route_maps (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    created_at  DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at  DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    instance_id INTEGER NOT NULL REFERENCES instances(id) ON DELETE CASCADE,
    name        TEXT NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    entries     TEXT NOT NULL DEFAULT '[]',
    UNIQUE (instance_id, name)
);

CREATE TABLE bgp_configs (
    id                         INTEGER PRIMARY KEY AUTOINCREMENT,
    created_at                 DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at                 DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    instance_id                INTEGER NOT NULL UNIQUE REFERENCES instances(id) ON DELETE CASCADE,
    enabled                    BOOLEAN NOT NULL DEFAULT false,
    asn                        INTEGER NOT NULL DEFAULT 0,
    router_id                  TEXT NOT NULL DEFAULT '',
    keepalive                  INTEGER NOT NULL DEFAULT 0,
    hold                       INTEGER NOT NULL DEFAULT 0,
    ebgp_requires_policy       BOOLEAN NOT NULL DEFAULT false,
    log_neighbor_changes       BOOLEAN NOT NULL DEFAULT true,
    graceful_restart           BOOLEAN NOT NULL DEFAULT false,
    multipath_relax            BOOLEAN NOT NULL DEFAULT false,
    maximum_paths              INTEGER NOT NULL DEFAULT 0,
    networks                   TEXT NOT NULL DEFAULT '[]',
    aggregates                 TEXT NOT NULL DEFAULT '[]',
    redist_connected_v4        BOOLEAN NOT NULL DEFAULT false,
    redist_connected_v4_map    TEXT NOT NULL DEFAULT '',
    redist_static_v4           BOOLEAN NOT NULL DEFAULT false,
    redist_static_v4_map       TEXT NOT NULL DEFAULT '',
    redist_connected_v6        BOOLEAN NOT NULL DEFAULT false,
    redist_connected_v6_map    TEXT NOT NULL DEFAULT '',
    redist_static_v6           BOOLEAN NOT NULL DEFAULT false,
    redist_static_v6_map       TEXT NOT NULL DEFAULT ''
);

CREATE TABLE bgp_peer_groups (
    id                          INTEGER PRIMARY KEY AUTOINCREMENT,
    created_at                  DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at                  DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    instance_id                 INTEGER NOT NULL REFERENCES instances(id) ON DELETE CASCADE,
    name                        TEXT NOT NULL,
    description                 TEXT NOT NULL DEFAULT '',
    remote_as                   TEXT NOT NULL DEFAULT '',
    password                    TEXT NOT NULL DEFAULT '',
    ebgp_multihop               INTEGER NOT NULL DEFAULT 0,
    update_source               TEXT NOT NULL DEFAULT '',
    passive                     BOOLEAN NOT NULL DEFAULT false,
    shutdown                    BOOLEAN NOT NULL DEFAULT false,
    keepalive                   INTEGER NOT NULL DEFAULT 0,
    hold                        INTEGER NOT NULL DEFAULT 0,
    v4_activate                 BOOLEAN NOT NULL DEFAULT false,
    v4_prefix_list_in           TEXT NOT NULL DEFAULT '',
    v4_prefix_list_out          TEXT NOT NULL DEFAULT '',
    v4_route_map_in             TEXT NOT NULL DEFAULT '',
    v4_route_map_out            TEXT NOT NULL DEFAULT '',
    v4_next_hop_self            BOOLEAN NOT NULL DEFAULT false,
    v4_remove_private_as        BOOLEAN NOT NULL DEFAULT false,
    v4_soft_reconfiguration     BOOLEAN NOT NULL DEFAULT false,
    v4_default_originate        BOOLEAN NOT NULL DEFAULT false,
    v4_route_reflector_client   BOOLEAN NOT NULL DEFAULT false,
    v4_allowas_in               INTEGER NOT NULL DEFAULT 0,
    v4_maximum_prefix           INTEGER NOT NULL DEFAULT 0,
    v6_activate                 BOOLEAN NOT NULL DEFAULT false,
    v6_prefix_list_in           TEXT NOT NULL DEFAULT '',
    v6_prefix_list_out          TEXT NOT NULL DEFAULT '',
    v6_route_map_in             TEXT NOT NULL DEFAULT '',
    v6_route_map_out            TEXT NOT NULL DEFAULT '',
    v6_next_hop_self            BOOLEAN NOT NULL DEFAULT false,
    v6_remove_private_as        BOOLEAN NOT NULL DEFAULT false,
    v6_soft_reconfiguration     BOOLEAN NOT NULL DEFAULT false,
    v6_default_originate        BOOLEAN NOT NULL DEFAULT false,
    v6_route_reflector_client   BOOLEAN NOT NULL DEFAULT false,
    v6_allowas_in               INTEGER NOT NULL DEFAULT 0,
    v6_maximum_prefix           INTEGER NOT NULL DEFAULT 0,
    UNIQUE (instance_id, name)
);

CREATE TABLE bgp_neighbors (
    id                          INTEGER PRIMARY KEY AUTOINCREMENT,
    created_at                  DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at                  DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    instance_id                 INTEGER NOT NULL REFERENCES instances(id) ON DELETE CASCADE,
    address                     TEXT NOT NULL,
    enabled                     BOOLEAN NOT NULL DEFAULT true,
    peer_group                  TEXT NOT NULL DEFAULT '',
    description                 TEXT NOT NULL DEFAULT '',
    remote_as                   TEXT NOT NULL DEFAULT '',
    password                    TEXT NOT NULL DEFAULT '',
    ebgp_multihop               INTEGER NOT NULL DEFAULT 0,
    update_source               TEXT NOT NULL DEFAULT '',
    passive                     BOOLEAN NOT NULL DEFAULT false,
    shutdown                    BOOLEAN NOT NULL DEFAULT false,
    keepalive                   INTEGER NOT NULL DEFAULT 0,
    hold                        INTEGER NOT NULL DEFAULT 0,
    v4_activate                 BOOLEAN NOT NULL DEFAULT false,
    v4_prefix_list_in           TEXT NOT NULL DEFAULT '',
    v4_prefix_list_out          TEXT NOT NULL DEFAULT '',
    v4_route_map_in             TEXT NOT NULL DEFAULT '',
    v4_route_map_out            TEXT NOT NULL DEFAULT '',
    v4_next_hop_self            BOOLEAN NOT NULL DEFAULT false,
    v4_remove_private_as        BOOLEAN NOT NULL DEFAULT false,
    v4_soft_reconfiguration     BOOLEAN NOT NULL DEFAULT false,
    v4_default_originate        BOOLEAN NOT NULL DEFAULT false,
    v4_route_reflector_client   BOOLEAN NOT NULL DEFAULT false,
    v4_allowas_in               INTEGER NOT NULL DEFAULT 0,
    v4_maximum_prefix           INTEGER NOT NULL DEFAULT 0,
    v6_activate                 BOOLEAN NOT NULL DEFAULT false,
    v6_prefix_list_in           TEXT NOT NULL DEFAULT '',
    v6_prefix_list_out          TEXT NOT NULL DEFAULT '',
    v6_route_map_in             TEXT NOT NULL DEFAULT '',
    v6_route_map_out            TEXT NOT NULL DEFAULT '',
    v6_next_hop_self            BOOLEAN NOT NULL DEFAULT false,
    v6_remove_private_as        BOOLEAN NOT NULL DEFAULT false,
    v6_soft_reconfiguration     BOOLEAN NOT NULL DEFAULT false,
    v6_default_originate        BOOLEAN NOT NULL DEFAULT false,
    v6_route_reflector_client   BOOLEAN NOT NULL DEFAULT false,
    v6_allowas_in               INTEGER NOT NULL DEFAULT 0,
    v6_maximum_prefix           INTEGER NOT NULL DEFAULT 0,
    UNIQUE (instance_id, address)
);

-- +goose Down
DROP TABLE bgp_neighbors;
DROP TABLE bgp_peer_groups;
DROP TABLE bgp_configs;
DROP TABLE route_maps;
DROP TABLE route_community_lists;
DROP TABLE route_as_path_lists;
DROP TABLE route_prefix_lists;
