-- SPDX-FileCopyrightText: 2026 The Portitor contributors
-- SPDX-License-Identifier: AGPL-3.0-or-later

-- +goose Up
-- IS-IS's NET made from an interface's IPv4 address (a loopback, say): the
-- area, and the interface by name. Empty: the NET is entered.
ALTER TABLE isis_configs ADD COLUMN net_interface TEXT NOT NULL DEFAULT '';
ALTER TABLE isis_configs ADD COLUMN net_area TEXT NOT NULL DEFAULT '';

-- +goose Down
ALTER TABLE isis_configs DROP COLUMN net_area;
ALTER TABLE isis_configs DROP COLUMN net_interface;
