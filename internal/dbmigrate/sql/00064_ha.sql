-- SPDX-FileCopyrightText: 2026 The Portitor contributors
-- SPDX-License-Identifier: AGPL-3.0-or-later

-- +goose Up
-- HA pairs: a firewall may be the secondary of another (ha_primary_id). It
-- has no instances of its own; it runs its primary's, with the peer_*
-- values in place of what must differ between the two hosts.
ALTER TABLE firewalls ADD COLUMN ha_primary_id INTEGER REFERENCES firewalls(id);
-- ha_secret is the pair's, on the secondary; ha_url is how the other host
-- reaches the agent (empty: agent_url).
ALTER TABLE firewalls ADD COLUMN ha_secret TEXT NOT NULL DEFAULT '';
ALTER TABLE firewalls ADD COLUMN ha_url TEXT NOT NULL DEFAULT '';
CREATE UNIQUE INDEX firewalls_ha_primary ON firewalls (ha_primary_id) WHERE ha_primary_id IS NOT NULL;
ALTER TABLE interfaces ADD COLUMN peer_addresses TEXT NOT NULL DEFAULT '[]';
ALTER TABLE vrrp_routers ADD COLUMN peer_priority INTEGER;
ALTER TABLE bgp_configs ADD COLUMN peer_router_id TEXT NOT NULL DEFAULT '';
ALTER TABLE ospf_configs ADD COLUMN peer_router_id TEXT NOT NULL DEFAULT '';
ALTER TABLE isis_configs ADD COLUMN peer_net TEXT NOT NULL DEFAULT '';

-- +goose Down
ALTER TABLE isis_configs DROP COLUMN peer_net;
ALTER TABLE ospf_configs DROP COLUMN peer_router_id;
ALTER TABLE bgp_configs DROP COLUMN peer_router_id;
ALTER TABLE vrrp_routers DROP COLUMN peer_priority;
ALTER TABLE interfaces DROP COLUMN peer_addresses;
DROP INDEX firewalls_ha_primary;
ALTER TABLE firewalls DROP COLUMN ha_url;
ALTER TABLE firewalls DROP COLUMN ha_secret;
ALTER TABLE firewalls DROP COLUMN ha_primary_id;
