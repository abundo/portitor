-- SPDX-FileCopyrightText: 2026 The Portitor contributors
-- SPDX-License-Identifier: AGPL-3.0-or-later

-- +goose Up
-- An interface in DHCP mode that takes no default route from its lease (a
-- LAN on DHCP; the default route belongs to the WAN).
ALTER TABLE interfaces ADD COLUMN dhcp_no_default_route BOOLEAN NOT NULL DEFAULT false;

-- +goose Down
ALTER TABLE interfaces DROP COLUMN dhcp_no_default_route;
