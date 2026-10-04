-- SPDX-FileCopyrightText: 2026 The Portitor contributors
-- SPDX-License-Identifier: AGPL-3.0-or-later

-- +goose Up
-- Rate limits, per instance, which rules name: they limit or shape.
CREATE TABLE rate_limits (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    created_at   DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at   DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    instance_id  INTEGER NOT NULL REFERENCES instances(id) ON DELETE CASCADE,
    name         TEXT NOT NULL,
    description  TEXT NOT NULL DEFAULT '',
    rate         INTEGER NOT NULL DEFAULT 10,
    per          TEXT NOT NULL DEFAULT 'second',
    unit         TEXT NOT NULL DEFAULT '',
    burst        INTEGER NOT NULL DEFAULT 0,
    per_source   BOOLEAN NOT NULL DEFAULT false,
    connections  BOOLEAN NOT NULL DEFAULT false,
    shape        BOOLEAN NOT NULL DEFAULT false,
    UNIQUE (instance_id, name)
);
ALTER TABLE rules ADD COLUMN rate_limit TEXT NOT NULL DEFAULT '';

-- +goose Down
ALTER TABLE rules DROP COLUMN rate_limit;
DROP TABLE rate_limits;
