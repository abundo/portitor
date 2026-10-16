-- SPDX-FileCopyrightText: 2026 The Portitor contributors
-- SPDX-License-Identifier: AGPL-3.0-or-later

-- +goose Up
-- Custom port names: NAT port fields take them next to the built-in ones
-- (fwconfig.Services); the builder writes their numbers.
CREATE TABLE port_names (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    created_at  DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at  DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    name        TEXT NOT NULL UNIQUE,
    port        INTEGER NOT NULL,
    description TEXT NOT NULL DEFAULT ''
);

-- +goose Down
DROP TABLE port_names;
