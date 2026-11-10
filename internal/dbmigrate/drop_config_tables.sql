-- SPDX-FileCopyrightText: 2026 The Portitor contributors
-- SPDX-License-Identifier: AGPL-3.0-or-later

-- +goose NO TRANSACTION
-- +goose Up
-- The configuration is the tree (candidate.json, deployed/<commit>-config.json),
-- no longer also kept in tables: they go. settings keeps what is not
-- configuration: the commit counter and the certificate portitor-config
-- serves (an id of the configuration's, config_ids).
PRAGMA foreign_keys = OFF;
BEGIN;
CREATE TABLE settings_new (
    id                 INTEGER PRIMARY KEY,
    last_commit        INTEGER NOT NULL DEFAULT 0,
    web_certificate_id INTEGER,
    updated_at         DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);
INSERT INTO settings_new (id, last_commit, web_certificate_id, updated_at)
    SELECT id, last_commit, web_certificate_id, updated_at FROM settings;
DROP TABLE settings;
ALTER TABLE settings_new RENAME TO settings;
DROP TABLE acme_proxy_policies;
DROP TABLE address_lists;
DROP TABLE address_objects;
DROP TABLE bfd_interfaces;
DROP TABLE bgp_configs;
DROP TABLE bgp_neighbors;
DROP TABLE bgp_peer_groups;
DROP TABLE certificates;
DROP TABLE dns_blocklists;
DROP TABLE dns_dnssec_policies;
DROP TABLE dns_records;
DROP TABLE dns_soa_templates;
DROP TABLE dns_templates;
DROP TABLE dns_zones;
DROP TABLE dyndns_clients;
DROP TABLE dyndns_records;
DROP TABLE instances;
DROP TABLE interface_zones;
DROP TABLE interfaces;
DROP TABLE ip_lists;
DROP TABLE ipam_addresses;
DROP TABLE ipam_prefixes;
DROP TABLE isis_configs;
DROP TABLE isis_interfaces;
DROP TABLE links;
DROP TABLE nat_rules;
DROP TABLE object_folders;
DROP TABLE ospf_configs;
DROP TABLE ospf_interfaces;
DROP TABLE policy_routes;
DROP TABLE port_names;
DROP TABLE rate_limits;
DROP TABLE route_as_path_lists;
DROP TABLE route_community_lists;
DROP TABLE route_maps;
DROP TABLE route_prefix_lists;
DROP TABLE routes;
DROP TABLE rules;
DROP TABLE services;
DROP TABLE snmp_users;
DROP TABLE static_neighbours;
DROP TABLE syslog_servers;
DROP TABLE tasks;
DROP TABLE vrfs;
DROP TABLE vrrp_routers;
DROP TABLE wg_peers;
COMMIT;
PRAGMA foreign_keys = ON;
