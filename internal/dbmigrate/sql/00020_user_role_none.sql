-- SPDX-FileCopyrightText: 2026 The Portitor contributors
-- SPDX-License-Identifier: AGPL-3.0-or-later

-- +goose NO TRANSACTION
-- +goose Up
-- A user's role may be 'none': no access of their own, only what their
-- roles grant on instances. SQLite cannot change a CHECK constraint, so the
-- table is rebuilt, keeping its AUTOINCREMENT counter.
PRAGMA foreign_keys = OFF;
BEGIN;
CREATE TABLE users_new (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    created_at    DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at    DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    username      TEXT NOT NULL UNIQUE,
    full_name     TEXT NOT NULL DEFAULT '',
    email         TEXT NOT NULL DEFAULT '',
    password_hash TEXT NOT NULL,
    token_version INTEGER NOT NULL DEFAULT 0,
    role          TEXT NOT NULL DEFAULT 'admin' CHECK (role IN ('admin', 'viewer', 'none'))
);
INSERT INTO users_new (id, created_at, updated_at, username, full_name, email, password_hash, token_version, role)
    SELECT id, created_at, updated_at, username, full_name, email, password_hash, token_version, role FROM users;
DELETE FROM sqlite_sequence WHERE name = 'users_new';
INSERT INTO sqlite_sequence (name, seq)
    SELECT 'users_new', seq FROM sqlite_sequence WHERE name = 'users';
DROP TABLE users;
ALTER TABLE users_new RENAME TO users;
COMMIT;
PRAGMA foreign_keys = ON;

-- +goose Down
PRAGMA foreign_keys = OFF;
BEGIN;
CREATE TABLE users_new (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    created_at    DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at    DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    username      TEXT NOT NULL UNIQUE,
    full_name     TEXT NOT NULL DEFAULT '',
    email         TEXT NOT NULL DEFAULT '',
    password_hash TEXT NOT NULL,
    token_version INTEGER NOT NULL DEFAULT 0,
    role          TEXT NOT NULL DEFAULT 'admin' CHECK (role IN ('admin', 'viewer'))
);
INSERT INTO users_new (id, created_at, updated_at, username, full_name, email, password_hash, token_version, role)
    SELECT id, created_at, updated_at, username, full_name, email, password_hash, token_version,
           CASE role WHEN 'none' THEN 'viewer' ELSE role END FROM users;
DELETE FROM sqlite_sequence WHERE name = 'users_new';
INSERT INTO sqlite_sequence (name, seq)
    SELECT 'users_new', seq FROM sqlite_sequence WHERE name = 'users';
DROP TABLE users;
ALTER TABLE users_new RENAME TO users;
COMMIT;
PRAGMA foreign_keys = ON;
