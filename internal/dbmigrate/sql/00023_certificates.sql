-- SPDX-FileCopyrightText: 2026 The Portitor contributors
-- SPDX-License-Identifier: AGPL-3.0-or-later

-- +goose Up
-- ACME (Let's Encrypt) certificates the agent gets and renews. domains is
-- a JSON array. Deleting an interface a certificate uses is refused (NO
-- ACTION, checked at the end of the statement, so deleting the whole
-- instance still works).
CREATE TABLE certificates (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    created_at   DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at   DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    instance_id  INTEGER NOT NULL REFERENCES instances(id) ON DELETE CASCADE,
    name         TEXT NOT NULL,
    description  TEXT NOT NULL DEFAULT '',
    enabled      BOOLEAN NOT NULL DEFAULT true,
    domains      TEXT NOT NULL DEFAULT '[]',
    email        TEXT NOT NULL DEFAULT '',
    ca           TEXT NOT NULL DEFAULT 'letsencrypt',
    key_type     TEXT NOT NULL DEFAULT 'ec256',
    challenge    TEXT NOT NULL DEFAULT 'http-01',
    interface_id INTEGER NOT NULL REFERENCES interfaces(id),
    UNIQUE (instance_id, name)
);

-- +goose Down
DROP TABLE certificates;
