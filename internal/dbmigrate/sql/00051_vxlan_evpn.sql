-- SPDX-FileCopyrightText: 2026 The Portitor contributors
-- SPDX-License-Identifier: AGPL-3.0-or-later

-- +goose Up
-- VXLAN interfaces (kind vxlan): the VNI, the local VTEP address, the
-- underlay interface (empty: as routed), the UDP port (0: 4789) and the
-- remote VTEPs (JSON list: the flood list, or with EVPN the VTEPs allowed
-- to send).
ALTER TABLE interfaces ADD COLUMN vxlan_vni INTEGER NOT NULL DEFAULT 0;
ALTER TABLE interfaces ADD COLUMN vxlan_local TEXT NOT NULL DEFAULT '';
ALTER TABLE interfaces ADD COLUMN vxlan_device TEXT NOT NULL DEFAULT '';
ALTER TABLE interfaces ADD COLUMN vxlan_port INTEGER NOT NULL DEFAULT 0;
ALTER TABLE interfaces ADD COLUMN vxlan_remotes TEXT NOT NULL DEFAULT '[]';
-- BGP EVPN: advertise the VXLANs' VNIs, and the L2VPN EVPN address family
-- per peer group and neighbour.
ALTER TABLE bgp_configs ADD COLUMN evpn BOOLEAN NOT NULL DEFAULT false;
ALTER TABLE bgp_peer_groups ADD COLUMN evpn_activate BOOLEAN NOT NULL DEFAULT false;
ALTER TABLE bgp_peer_groups ADD COLUMN evpn_route_reflector_client BOOLEAN NOT NULL DEFAULT false;
ALTER TABLE bgp_neighbors ADD COLUMN evpn_activate BOOLEAN NOT NULL DEFAULT false;
ALTER TABLE bgp_neighbors ADD COLUMN evpn_route_reflector_client BOOLEAN NOT NULL DEFAULT false;

-- +goose Down
ALTER TABLE bgp_neighbors DROP COLUMN evpn_route_reflector_client;
ALTER TABLE bgp_neighbors DROP COLUMN evpn_activate;
ALTER TABLE bgp_peer_groups DROP COLUMN evpn_route_reflector_client;
ALTER TABLE bgp_peer_groups DROP COLUMN evpn_activate;
ALTER TABLE bgp_configs DROP COLUMN evpn;
ALTER TABLE interfaces DROP COLUMN vxlan_remotes;
ALTER TABLE interfaces DROP COLUMN vxlan_port;
ALTER TABLE interfaces DROP COLUMN vxlan_device;
ALTER TABLE interfaces DROP COLUMN vxlan_local;
ALTER TABLE interfaces DROP COLUMN vxlan_vni;
