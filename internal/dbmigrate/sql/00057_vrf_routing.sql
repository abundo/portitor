-- SPDX-FileCopyrightText: 2026 The Portitor contributors
-- SPDX-License-Identifier: AGPL-3.0-or-later

-- +goose NO TRANSACTION
-- +goose Up
-- Routing protocols in VRFs: BGP, OSPF and IS-IS configs, BGP neighbours
-- and peer groups get a VRF (vrf_id; NULL is the main table). A config is
-- then one per instance (and version) and VRF, a neighbour's address once
-- per instance and VRF: SQLite cannot drop a UNIQUE constraint, so those
-- tables are rebuilt, keeping their AUTOINCREMENT counters. Peer group
-- names stay unique per instance. Deleting a VRF is refused while it has
-- enabled routing or neighbours (web/vrf.go); what is left goes with it.
PRAGMA foreign_keys = OFF;
BEGIN;
ALTER TABLE bgp_peer_groups ADD COLUMN vrf_id INTEGER REFERENCES vrfs(id) ON DELETE CASCADE;

-- bgp_configs: one per instance and VRF.
CREATE TABLE bgp_configs_new (
    id                      INTEGER PRIMARY KEY AUTOINCREMENT,
    created_at              DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at              DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    instance_id             INTEGER NOT NULL REFERENCES instances(id) ON DELETE CASCADE,
    enabled                 BOOLEAN NOT NULL DEFAULT false,
    asn                     INTEGER NOT NULL DEFAULT 0,
    router_id               TEXT NOT NULL DEFAULT '',
    keepalive               INTEGER NOT NULL DEFAULT 0,
    hold                    INTEGER NOT NULL DEFAULT 0,
    ebgp_requires_policy    BOOLEAN NOT NULL DEFAULT false,
    log_neighbor_changes    BOOLEAN NOT NULL DEFAULT true,
    graceful_restart        BOOLEAN NOT NULL DEFAULT false,
    multipath_relax         BOOLEAN NOT NULL DEFAULT false,
    maximum_paths           INTEGER NOT NULL DEFAULT 0,
    networks                TEXT NOT NULL DEFAULT '[]',
    aggregates              TEXT NOT NULL DEFAULT '[]',
    redist_connected_v4     BOOLEAN NOT NULL DEFAULT false,
    redist_connected_v4_map TEXT NOT NULL DEFAULT '',
    redist_static_v4        BOOLEAN NOT NULL DEFAULT false,
    redist_static_v4_map    TEXT NOT NULL DEFAULT '',
    redist_connected_v6     BOOLEAN NOT NULL DEFAULT false,
    redist_connected_v6_map TEXT NOT NULL DEFAULT '',
    redist_static_v6        BOOLEAN NOT NULL DEFAULT false,
    redist_static_v6_map    TEXT NOT NULL DEFAULT '',
    redist_ospf_v4          BOOLEAN NOT NULL DEFAULT false,
    redist_ospf_v4_map      TEXT NOT NULL DEFAULT '',
    redist_ospf_v6          BOOLEAN NOT NULL DEFAULT false,
    redist_ospf_v6_map      TEXT NOT NULL DEFAULT '',
    evpn                    BOOLEAN NOT NULL DEFAULT false,
    redist_isis_v4          BOOLEAN NOT NULL DEFAULT false,
    redist_isis_v4_map      TEXT NOT NULL DEFAULT '',
    redist_isis_v6          BOOLEAN NOT NULL DEFAULT false,
    redist_isis_v6_map      TEXT NOT NULL DEFAULT '',
    vrf_id                  INTEGER REFERENCES vrfs(id) ON DELETE CASCADE
);
INSERT INTO bgp_configs_new (id, created_at, updated_at, instance_id, enabled, asn, router_id, keepalive, hold, ebgp_requires_policy, log_neighbor_changes, graceful_restart, multipath_relax, maximum_paths, networks, aggregates, redist_connected_v4, redist_connected_v4_map, redist_static_v4, redist_static_v4_map, redist_connected_v6, redist_connected_v6_map, redist_static_v6, redist_static_v6_map, redist_ospf_v4, redist_ospf_v4_map, redist_ospf_v6, redist_ospf_v6_map, evpn, redist_isis_v4, redist_isis_v4_map, redist_isis_v6, redist_isis_v6_map)
    SELECT id, created_at, updated_at, instance_id, enabled, asn, router_id, keepalive, hold, ebgp_requires_policy, log_neighbor_changes, graceful_restart, multipath_relax, maximum_paths, networks, aggregates, redist_connected_v4, redist_connected_v4_map, redist_static_v4, redist_static_v4_map, redist_connected_v6, redist_connected_v6_map, redist_static_v6, redist_static_v6_map, redist_ospf_v4, redist_ospf_v4_map, redist_ospf_v6, redist_ospf_v6_map, evpn, redist_isis_v4, redist_isis_v4_map, redist_isis_v6, redist_isis_v6_map FROM bgp_configs;
DELETE FROM sqlite_sequence WHERE name = 'bgp_configs_new';
INSERT INTO sqlite_sequence (name, seq) SELECT 'bgp_configs_new', seq FROM sqlite_sequence WHERE name = 'bgp_configs';
DROP TABLE bgp_configs;
ALTER TABLE bgp_configs_new RENAME TO bgp_configs;
CREATE UNIQUE INDEX bgp_configs_vrf ON bgp_configs (instance_id, IFNULL(vrf_id, 0));

-- ospf_configs: one per instance, version and VRF.
CREATE TABLE ospf_configs_new (
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
    vrf_id                INTEGER REFERENCES vrfs(id) ON DELETE CASCADE
);
INSERT INTO ospf_configs_new (id, created_at, updated_at, instance_id, version, enabled, router_id, reference_bandwidth, log_adjacency_changes, maximum_paths, default_originate, default_always, areas, ranges, summaries, networks, redistribute)
    SELECT id, created_at, updated_at, instance_id, version, enabled, router_id, reference_bandwidth, log_adjacency_changes, maximum_paths, default_originate, default_always, areas, ranges, summaries, networks, redistribute FROM ospf_configs;
DELETE FROM sqlite_sequence WHERE name = 'ospf_configs_new';
INSERT INTO sqlite_sequence (name, seq) SELECT 'ospf_configs_new', seq FROM sqlite_sequence WHERE name = 'ospf_configs';
DROP TABLE ospf_configs;
ALTER TABLE ospf_configs_new RENAME TO ospf_configs;
CREATE UNIQUE INDEX ospf_configs_vrf ON ospf_configs (instance_id, version, IFNULL(vrf_id, 0));

-- isis_configs: one per instance and VRF.
CREATE TABLE isis_configs_new (
    id                    INTEGER PRIMARY KEY AUTOINCREMENT,
    created_at            DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at            DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    instance_id           INTEGER NOT NULL REFERENCES instances(id) ON DELETE CASCADE,
    enabled               BOOLEAN NOT NULL DEFAULT false,
    net                   TEXT NOT NULL DEFAULT '',
    level                 TEXT NOT NULL DEFAULT '',
    metric_style          TEXT NOT NULL DEFAULT '',
    log_adjacency_changes BOOLEAN NOT NULL DEFAULT true,
    ipv6_topology         BOOLEAN NOT NULL DEFAULT false,
    overload              BOOLEAN NOT NULL DEFAULT false,
    default_originate     TEXT NOT NULL DEFAULT '[]',
    redistribute          TEXT NOT NULL DEFAULT '[]',
    area_password         TEXT NOT NULL DEFAULT '',
    area_password_type    TEXT NOT NULL DEFAULT 'md5',
    domain_password       TEXT NOT NULL DEFAULT '',
    domain_password_type  TEXT NOT NULL DEFAULT 'md5',
    net_interface         TEXT NOT NULL DEFAULT '',
    net_area              TEXT NOT NULL DEFAULT '',
    vrf_id                INTEGER REFERENCES vrfs(id) ON DELETE CASCADE
);
INSERT INTO isis_configs_new (id, created_at, updated_at, instance_id, enabled, net, level, metric_style, log_adjacency_changes, ipv6_topology, overload, default_originate, redistribute, area_password, area_password_type, domain_password, domain_password_type, net_interface, net_area)
    SELECT id, created_at, updated_at, instance_id, enabled, net, level, metric_style, log_adjacency_changes, ipv6_topology, overload, default_originate, redistribute, area_password, area_password_type, domain_password, domain_password_type, net_interface, net_area FROM isis_configs;
DELETE FROM sqlite_sequence WHERE name = 'isis_configs_new';
INSERT INTO sqlite_sequence (name, seq) SELECT 'isis_configs_new', seq FROM sqlite_sequence WHERE name = 'isis_configs';
DROP TABLE isis_configs;
ALTER TABLE isis_configs_new RENAME TO isis_configs;
CREATE UNIQUE INDEX isis_configs_vrf ON isis_configs (instance_id, IFNULL(vrf_id, 0));

-- bgp_neighbors: an address once per instance and VRF.
CREATE TABLE bgp_neighbors_new (
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
    interface                   TEXT NOT NULL DEFAULT '',
    bfd                         BOOLEAN NOT NULL DEFAULT false,
    evpn_activate               BOOLEAN NOT NULL DEFAULT false,
    evpn_route_reflector_client BOOLEAN NOT NULL DEFAULT false,
    vrf_id                      INTEGER REFERENCES vrfs(id) ON DELETE CASCADE
);
INSERT INTO bgp_neighbors_new (id, created_at, updated_at, instance_id, address, enabled, peer_group, description, remote_as, password, ebgp_multihop, update_source, passive, shutdown, keepalive, hold, v4_activate, v4_prefix_list_in, v4_prefix_list_out, v4_route_map_in, v4_route_map_out, v4_next_hop_self, v4_remove_private_as, v4_soft_reconfiguration, v4_default_originate, v4_route_reflector_client, v4_allowas_in, v4_maximum_prefix, v6_activate, v6_prefix_list_in, v6_prefix_list_out, v6_route_map_in, v6_route_map_out, v6_next_hop_self, v6_remove_private_as, v6_soft_reconfiguration, v6_default_originate, v6_route_reflector_client, v6_allowas_in, v6_maximum_prefix, interface, bfd, evpn_activate, evpn_route_reflector_client)
    SELECT id, created_at, updated_at, instance_id, address, enabled, peer_group, description, remote_as, password, ebgp_multihop, update_source, passive, shutdown, keepalive, hold, v4_activate, v4_prefix_list_in, v4_prefix_list_out, v4_route_map_in, v4_route_map_out, v4_next_hop_self, v4_remove_private_as, v4_soft_reconfiguration, v4_default_originate, v4_route_reflector_client, v4_allowas_in, v4_maximum_prefix, v6_activate, v6_prefix_list_in, v6_prefix_list_out, v6_route_map_in, v6_route_map_out, v6_next_hop_self, v6_remove_private_as, v6_soft_reconfiguration, v6_default_originate, v6_route_reflector_client, v6_allowas_in, v6_maximum_prefix, interface, bfd, evpn_activate, evpn_route_reflector_client FROM bgp_neighbors;
DELETE FROM sqlite_sequence WHERE name = 'bgp_neighbors_new';
INSERT INTO sqlite_sequence (name, seq) SELECT 'bgp_neighbors_new', seq FROM sqlite_sequence WHERE name = 'bgp_neighbors';
DROP TABLE bgp_neighbors;
ALTER TABLE bgp_neighbors_new RENAME TO bgp_neighbors;
CREATE UNIQUE INDEX bgp_neighbors_vrf ON bgp_neighbors (instance_id, IFNULL(vrf_id, 0), address);

COMMIT;
PRAGMA foreign_keys = ON;

-- +goose Down
-- The VRFs' routing is dropped; the columns stay (SQLite can't drop a
-- column with a foreign key).
DELETE FROM bgp_neighbors WHERE vrf_id IS NOT NULL;
DELETE FROM bgp_peer_groups WHERE vrf_id IS NOT NULL;
DELETE FROM bgp_configs WHERE vrf_id IS NOT NULL;
DELETE FROM ospf_configs WHERE vrf_id IS NOT NULL;
DELETE FROM isis_configs WHERE vrf_id IS NOT NULL;
