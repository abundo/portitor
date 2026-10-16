-- SPDX-FileCopyrightText: 2026 The Portitor contributors
-- SPDX-License-Identifier: AGPL-3.0-or-later

-- +goose Up
-- Static neighbours: permanent ARP (IPv4) and ND (IPv6) entries, address
-- to MAC on an interface; removed with their interface.
CREATE TABLE static_neighbours (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    created_at   DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at   DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    instance_id  INTEGER NOT NULL REFERENCES instances(id) ON DELETE CASCADE,
    interface_id INTEGER NOT NULL REFERENCES interfaces(id) ON DELETE CASCADE,
    address      TEXT NOT NULL,
    mac          TEXT NOT NULL,
    enabled      BOOLEAN NOT NULL DEFAULT true,
    description  TEXT NOT NULL DEFAULT '',
    UNIQUE (interface_id, address)
);

-- +goose Down
DROP TABLE static_neighbours;
