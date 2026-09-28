-- SPDX-FileCopyrightText: 2026 The Portitor contributors
-- SPDX-License-Identifier: AGPL-3.0-or-later

-- +goose Up
-- Custom services: port names that rule and NAT port lists accept like the
-- built-in ones (fwconfig.Services). ports is a port list ("8000-8080",
-- "80, 443"); the builder expands the name into it.
CREATE TABLE services (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    created_at  DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at  DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    name        TEXT NOT NULL UNIQUE,
    ports       TEXT NOT NULL,
    description TEXT NOT NULL DEFAULT ''
);

-- +goose Down
DROP TABLE services;
