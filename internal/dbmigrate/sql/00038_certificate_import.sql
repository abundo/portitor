-- SPDX-FileCopyrightText: 2026 The Portitor contributors
-- SPDX-License-Identifier: AGPL-3.0-or-later

-- +goose NO TRANSACTION
-- +goose Up
-- Imported certificates: a chain and key instead of ACME, with no
-- interface. The table is rebuilt to make interface_id nullable, keeping
-- its AUTOINCREMENT counter.
PRAGMA foreign_keys = OFF;
BEGIN;
CREATE TABLE certificates_new (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    created_at   DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at   DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    instance_id  INTEGER NOT NULL REFERENCES instances(id) ON DELETE CASCADE,
    name         TEXT NOT NULL,
    description  TEXT NOT NULL DEFAULT '',
    enabled      BOOLEAN NOT NULL DEFAULT true,
    source       TEXT NOT NULL DEFAULT 'acme',
    domains      TEXT NOT NULL DEFAULT '[]',
    common_name  TEXT NOT NULL DEFAULT '',
    email        TEXT NOT NULL DEFAULT '',
    ca           TEXT NOT NULL DEFAULT 'letsencrypt',
    key_type     TEXT NOT NULL DEFAULT 'ec256',
    challenge    TEXT NOT NULL DEFAULT 'http-01',
    interface_id INTEGER REFERENCES interfaces(id),
    full_chain   TEXT NOT NULL DEFAULT '',
    priv_key     TEXT NOT NULL DEFAULT '',
    UNIQUE (instance_id, name)
);
INSERT INTO certificates_new (id, created_at, updated_at, instance_id, name, description, enabled, domains,
        common_name, email, ca, key_type, challenge, interface_id)
    SELECT id, created_at, updated_at, instance_id, name, description, enabled, domains,
        common_name, email, ca, key_type, challenge, interface_id
    FROM certificates;
DELETE FROM sqlite_sequence WHERE name = 'certificates_new';
INSERT INTO sqlite_sequence (name, seq)
    SELECT 'certificates_new', seq FROM sqlite_sequence WHERE name = 'certificates';
DROP TABLE certificates;
ALTER TABLE certificates_new RENAME TO certificates;
COMMIT;
PRAGMA foreign_keys = ON;

-- +goose Down
-- Imported certificates have no interface.
SELECT 1;
