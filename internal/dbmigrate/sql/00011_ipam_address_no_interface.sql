-- SPDX-FileCopyrightText: 2026 The Portitor contributors
-- SPDX-License-Identifier: AGPL-3.0-or-later

-- +goose NO TRANSACTION
-- +goose Up
-- IPAM addresses no longer name an interface (migration 10 moved those to
-- interfaces.addresses). SQLite cannot drop a column with a foreign key, so
-- the table is rebuilt, keeping its AUTOINCREMENT counter.
PRAGMA foreign_keys = OFF;
BEGIN;
CREATE TABLE ipam_addresses_new (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    created_at   DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at   DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    instance_id  INTEGER NOT NULL REFERENCES instances(id) ON DELETE CASCADE,
    address      TEXT NOT NULL,
    dns_name     TEXT NOT NULL DEFAULT '',
    mac          TEXT NOT NULL DEFAULT '',
    description  TEXT NOT NULL DEFAULT '',
    UNIQUE (instance_id, address)
);
INSERT INTO ipam_addresses_new (id, created_at, updated_at, instance_id, address, dns_name, mac, description)
    SELECT id, created_at, updated_at, instance_id, address, dns_name, mac, description FROM ipam_addresses;
DELETE FROM sqlite_sequence WHERE name = 'ipam_addresses_new';
INSERT INTO sqlite_sequence (name, seq)
    SELECT 'ipam_addresses_new', seq FROM sqlite_sequence WHERE name = 'ipam_addresses';
DROP TABLE ipam_addresses;
ALTER TABLE ipam_addresses_new RENAME TO ipam_addresses;
COMMIT;
PRAGMA foreign_keys = ON;

-- +goose Down
ALTER TABLE ipam_addresses ADD COLUMN interface_id INTEGER REFERENCES interfaces(id) ON DELETE SET NULL;
