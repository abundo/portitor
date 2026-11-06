-- SPDX-FileCopyrightText: 2026 The Portitor contributors
-- SPDX-License-Identifier: AGPL-3.0-or-later

-- +goose Up
-- An HA pair is active and passive with the same addresses: only its two
-- own links differ between the hosts (fwconfig.Interface.HARole), so what
-- the secondary had of its own for VRRP goes.
ALTER TABLE interfaces ADD COLUMN ha_role TEXT NOT NULL DEFAULT '';
ALTER TABLE interfaces ADD COLUMN ha_gateway TEXT NOT NULL DEFAULT '';
ALTER TABLE vrrp_routers DROP COLUMN peer_priority;
ALTER TABLE bgp_configs DROP COLUMN peer_router_id;
ALTER TABLE ospf_configs DROP COLUMN peer_router_id;
ALTER TABLE isis_configs DROP COLUMN peer_net;
ALTER TABLE bgp_neighbors DROP COLUMN ha_peer_address;

-- +goose Down
ALTER TABLE bgp_neighbors ADD COLUMN ha_peer_address TEXT NOT NULL DEFAULT '';
ALTER TABLE isis_configs ADD COLUMN peer_net TEXT NOT NULL DEFAULT '';
ALTER TABLE ospf_configs ADD COLUMN peer_router_id TEXT NOT NULL DEFAULT '';
ALTER TABLE bgp_configs ADD COLUMN peer_router_id TEXT NOT NULL DEFAULT '';
ALTER TABLE vrrp_routers ADD COLUMN peer_priority INTEGER;
ALTER TABLE interfaces DROP COLUMN ha_gateway;
ALTER TABLE interfaces DROP COLUMN ha_role;
