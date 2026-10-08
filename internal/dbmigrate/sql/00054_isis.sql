-- SPDX-FileCopyrightText: 2026 The Portitor contributors
-- SPDX-License-Identifier: AGPL-3.0-or-later

-- +goose Up
-- IS-IS (FRR's isisd), one per instance. Lists are JSON arrays; route
-- maps are referred to by name, interfaces by name.
CREATE TABLE isis_configs (
    id                    INTEGER PRIMARY KEY AUTOINCREMENT,
    created_at            DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at            DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    instance_id           INTEGER NOT NULL UNIQUE REFERENCES instances(id) ON DELETE CASCADE,
    enabled               BOOLEAN NOT NULL DEFAULT false,
    net                   TEXT NOT NULL DEFAULT '',
    level                 TEXT NOT NULL DEFAULT '',
    metric_style          TEXT NOT NULL DEFAULT '',
    log_adjacency_changes BOOLEAN NOT NULL DEFAULT true,
    ipv6_topology         BOOLEAN NOT NULL DEFAULT false,
    overload              BOOLEAN NOT NULL DEFAULT false,
    default_originate     TEXT NOT NULL DEFAULT '[]',
    redistribute          TEXT NOT NULL DEFAULT '[]'
);

CREATE TABLE isis_interfaces (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    created_at       DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at       DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    instance_id      INTEGER NOT NULL REFERENCES instances(id) ON DELETE CASCADE,
    name             TEXT NOT NULL,
    ipv4             BOOLEAN NOT NULL DEFAULT true,
    ipv6             BOOLEAN NOT NULL DEFAULT false,
    circuit_type     TEXT NOT NULL DEFAULT '',
    point_to_point   BOOLEAN NOT NULL DEFAULT false,
    passive          BOOLEAN NOT NULL DEFAULT false,
    metric           INTEGER NOT NULL DEFAULT 0,
    hello_interval   INTEGER NOT NULL DEFAULT 0,
    hello_multiplier INTEGER NOT NULL DEFAULT 0,
    priority         INTEGER,
    bfd              BOOLEAN NOT NULL DEFAULT false,
    UNIQUE (instance_id, name)
);

-- +goose Down
DROP TABLE isis_interfaces;
DROP TABLE isis_configs;
