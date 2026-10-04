-- SPDX-FileCopyrightText: 2026 The Portitor contributors
-- SPDX-License-Identifier: AGPL-3.0-or-later

-- +goose Up
-- VRRP virtual routers (FRR's vrrpd), per instance, on an interface by
-- name. ipv4 and ipv6 are JSON arrays of addresses; a disabled one is
-- shut down (backup for good).
CREATE TABLE vrrp_routers (
    id                     INTEGER PRIMARY KEY AUTOINCREMENT,
    created_at             DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at             DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    instance_id            INTEGER NOT NULL REFERENCES instances(id) ON DELETE CASCADE,
    interface              TEXT NOT NULL,
    vrid                   INTEGER NOT NULL,
    version                INTEGER NOT NULL DEFAULT 3,
    priority               INTEGER NOT NULL DEFAULT 100,
    advertisement_interval INTEGER NOT NULL DEFAULT 1000,
    preempt                BOOLEAN NOT NULL DEFAULT true,
    enabled                BOOLEAN NOT NULL DEFAULT true,
    ipv4                   TEXT NOT NULL DEFAULT '[]',
    ipv6                   TEXT NOT NULL DEFAULT '[]',
    description            TEXT NOT NULL DEFAULT '',
    UNIQUE (instance_id, interface, vrid)
);

-- +goose Down
DROP TABLE vrrp_routers;
