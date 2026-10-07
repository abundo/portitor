-- SPDX-FileCopyrightText: 2026 The Portitor contributors
-- SPDX-License-Identifier: AGPL-3.0-or-later

-- +goose Up
-- VRF interfaces (kind vrf): the routing table; their members are in
-- members, as a bridge's.
ALTER TABLE interfaces ADD COLUMN vrf_table INTEGER NOT NULL DEFAULT 0;
-- A static route's VRF (an interface of kind vrf; NULL: the main table, or
-- the VRF of the route's interface).
ALTER TABLE routes ADD COLUMN vrf_id INTEGER REFERENCES interfaces(id) ON DELETE CASCADE;

-- +goose Down
ALTER TABLE routes DROP COLUMN vrf_id;
ALTER TABLE interfaces DROP COLUMN vrf_table;
