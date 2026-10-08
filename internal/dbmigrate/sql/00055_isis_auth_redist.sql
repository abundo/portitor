-- SPDX-FileCopyrightText: 2026 The Portitor contributors
-- SPDX-License-Identifier: AGPL-3.0-or-later

-- +goose Up
-- IS-IS authentication: area and domain passwords, and per interface the
-- hello password; each clear text or HMAC-MD5. The passwords are secrets.
ALTER TABLE isis_configs ADD COLUMN area_password TEXT NOT NULL DEFAULT '';
ALTER TABLE isis_configs ADD COLUMN area_password_type TEXT NOT NULL DEFAULT 'md5';
ALTER TABLE isis_configs ADD COLUMN domain_password TEXT NOT NULL DEFAULT '';
ALTER TABLE isis_configs ADD COLUMN domain_password_type TEXT NOT NULL DEFAULT 'md5';
ALTER TABLE isis_interfaces ADD COLUMN password TEXT NOT NULL DEFAULT '';
ALTER TABLE isis_interfaces ADD COLUMN password_type TEXT NOT NULL DEFAULT 'md5';

-- BGP redistributes IS-IS's routes, per IP version.
ALTER TABLE bgp_configs ADD COLUMN redist_isis_v4 BOOLEAN NOT NULL DEFAULT false;
ALTER TABLE bgp_configs ADD COLUMN redist_isis_v4_map TEXT NOT NULL DEFAULT '';
ALTER TABLE bgp_configs ADD COLUMN redist_isis_v6 BOOLEAN NOT NULL DEFAULT false;
ALTER TABLE bgp_configs ADD COLUMN redist_isis_v6_map TEXT NOT NULL DEFAULT '';

-- +goose Down
ALTER TABLE bgp_configs DROP COLUMN redist_isis_v6_map;
ALTER TABLE bgp_configs DROP COLUMN redist_isis_v6;
ALTER TABLE bgp_configs DROP COLUMN redist_isis_v4_map;
ALTER TABLE bgp_configs DROP COLUMN redist_isis_v4;
ALTER TABLE isis_interfaces DROP COLUMN password_type;
ALTER TABLE isis_interfaces DROP COLUMN password;
ALTER TABLE isis_configs DROP COLUMN domain_password_type;
ALTER TABLE isis_configs DROP COLUMN domain_password;
ALTER TABLE isis_configs DROP COLUMN area_password_type;
ALTER TABLE isis_configs DROP COLUMN area_password;
