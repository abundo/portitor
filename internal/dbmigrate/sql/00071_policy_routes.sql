-- SPDX-FileCopyrightText: 2026 The Portitor contributors
-- SPDX-License-Identifier: AGPL-3.0-or-later

-- +goose Up
-- Policy routes: forwarded traffic matched like a forward rule's (incoming
-- interfaces and zones, addresses, services; by name) is routed by a
-- gateway and/or interface of its own; neither is an exception that keeps
-- the main table. Tried by position, the first match decides. Removed with
-- their interface, as static routes are.
CREATE TABLE policy_routes (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    created_at    DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at    DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    instance_id   INTEGER NOT NULL REFERENCES instances(id) ON DELETE CASCADE,
    position      INTEGER NOT NULL DEFAULT 0,
    in_interfaces TEXT NOT NULL DEFAULT '[]',
    family        TEXT NOT NULL DEFAULT '',
    src_addrs     TEXT NOT NULL DEFAULT '[]',
    dst_addrs     TEXT NOT NULL DEFAULT '[]',
    services      TEXT NOT NULL DEFAULT '[]',
    gateway       TEXT NOT NULL DEFAULT '',
    interface_id  INTEGER REFERENCES interfaces(id) ON DELETE CASCADE,
    enabled       BOOLEAN NOT NULL DEFAULT true,
    description   TEXT NOT NULL DEFAULT ''
);
CREATE INDEX policy_routes_instance_position ON policy_routes (instance_id, position);

-- +goose Down
DROP TABLE policy_routes;
