-- SPDX-FileCopyrightText: 2026 The Portitor contributors
-- SPDX-License-Identifier: AGPL-3.0-or-later

-- +goose Up
-- Address lists: named lists of addresses, prefixes and names of hosts or
-- other address lists. They share their names with address_objects; a
-- filter rule using one gets an nftables set, elsewhere it is expanded.
CREATE TABLE address_lists (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    created_at  DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at  DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    name        TEXT NOT NULL UNIQUE,
    entries     TEXT NOT NULL DEFAULT '[]',
    description TEXT NOT NULL DEFAULT '',
    folder_id   INTEGER REFERENCES object_folders(id)
);

-- +goose Down
DROP TABLE address_lists;
