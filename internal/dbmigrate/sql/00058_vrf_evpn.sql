-- SPDX-FileCopyrightText: 2026 The Portitor contributors
-- SPDX-License-Identifier: AGPL-3.0-or-later

-- +goose Up
-- A VRF's L3VPN over EVPN/VXLAN: its L3VNI (0: off), VTEP, underlay, UDP
-- port, route distinguisher, route targets and the IP versions advertised.
ALTER TABLE vrfs ADD COLUMN evpn_vni INTEGER NOT NULL DEFAULT 0;
ALTER TABLE vrfs ADD COLUMN evpn_local TEXT NOT NULL DEFAULT '';
ALTER TABLE vrfs ADD COLUMN evpn_device TEXT NOT NULL DEFAULT '';
ALTER TABLE vrfs ADD COLUMN evpn_port INTEGER NOT NULL DEFAULT 0;
ALTER TABLE vrfs ADD COLUMN evpn_rd TEXT NOT NULL DEFAULT '';
ALTER TABLE vrfs ADD COLUMN evpn_import_rts TEXT NOT NULL DEFAULT '[]';
ALTER TABLE vrfs ADD COLUMN evpn_export_rts TEXT NOT NULL DEFAULT '[]';
ALTER TABLE vrfs ADD COLUMN evpn_advertise_v4 BOOLEAN NOT NULL DEFAULT true;
ALTER TABLE vrfs ADD COLUMN evpn_advertise_v6 BOOLEAN NOT NULL DEFAULT true;

-- +goose Down
ALTER TABLE vrfs DROP COLUMN evpn_vni;
ALTER TABLE vrfs DROP COLUMN evpn_local;
ALTER TABLE vrfs DROP COLUMN evpn_device;
ALTER TABLE vrfs DROP COLUMN evpn_port;
ALTER TABLE vrfs DROP COLUMN evpn_rd;
ALTER TABLE vrfs DROP COLUMN evpn_import_rts;
ALTER TABLE vrfs DROP COLUMN evpn_export_rts;
ALTER TABLE vrfs DROP COLUMN evpn_advertise_v4;
ALTER TABLE vrfs DROP COLUMN evpn_advertise_v6;
