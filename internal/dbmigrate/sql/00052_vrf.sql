-- SPDX-FileCopyrightText: 2026 The Portitor contributors
-- SPDX-License-Identifier: AGPL-3.0-or-later

-- +goose Up
-- VRFs of a virtual firewall (Routing → VRF): a name (that of its Linux vrf
-- device) and a routing table, both unique in the virtual firewall.
CREATE TABLE vrfs (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    created_at  DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at  DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    instance_id INTEGER NOT NULL REFERENCES instances(id) ON DELETE CASCADE,
    name        TEXT NOT NULL,
    route_table INTEGER NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    UNIQUE (instance_id, name),
    UNIQUE (instance_id, route_table)
);
-- The VRF an interface is in, by name; empty: the main table.
ALTER TABLE interfaces ADD COLUMN vrf TEXT NOT NULL DEFAULT '';
-- A static route's VRF (NULL: the main table, or the VRF of the route's
-- interface).
ALTER TABLE routes ADD COLUMN vrf_id INTEGER REFERENCES vrfs(id);

-- +goose Down
ALTER TABLE routes DROP COLUMN vrf_id;
ALTER TABLE interfaces DROP COLUMN vrf;
DROP TABLE vrfs;
