-- SPDX-FileCopyrightText: 2026 The Portitor contributors
-- SPDX-License-Identifier: AGPL-3.0-or-later

-- +goose NO TRANSACTION
-- +goose Up
-- Roles name their virtual firewall instead of pointing at its row: the
-- configuration is a tree, not the tables, and a role outlives a rename or
-- a delete until the commit. The tables are rebuilt to drop the foreign keys,
-- keeping their AUTOINCREMENT counters.
PRAGMA foreign_keys = OFF;
BEGIN;
CREATE TABLE roles_new (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    created_at   DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at   DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    name         TEXT NOT NULL UNIQUE,
    description  TEXT NOT NULL DEFAULT '',
    instance     TEXT UNIQUE
);
INSERT INTO roles_new (id, created_at, updated_at, name, description, instance)
    SELECT r.id, r.created_at, r.updated_at, r.name, r.description, i.name
    FROM roles r LEFT JOIN instances i ON i.id = r.instance_id;
DELETE FROM sqlite_sequence WHERE name = 'roles_new';
INSERT INTO sqlite_sequence (name, seq)
    SELECT 'roles_new', seq FROM sqlite_sequence WHERE name = 'roles';
DROP TABLE roles;
ALTER TABLE roles_new RENAME TO roles;

CREATE TABLE role_instances_new (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    created_at   DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at   DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    role_id      INTEGER NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
    instance     TEXT NOT NULL,
    UNIQUE (role_id, instance)
);
INSERT INTO role_instances_new (id, created_at, updated_at, role_id, instance)
    SELECT ri.id, ri.created_at, ri.updated_at, ri.role_id, i.name
    FROM role_instances ri JOIN instances i ON i.id = ri.instance_id;
DELETE FROM sqlite_sequence WHERE name = 'role_instances_new';
INSERT INTO sqlite_sequence (name, seq)
    SELECT 'role_instances_new', seq FROM sqlite_sequence WHERE name = 'role_instances';
DROP TABLE role_instances;
ALTER TABLE role_instances_new RENAME TO role_instances;
COMMIT;
PRAGMA foreign_keys = ON;

-- +goose Down
-- Grants and roles of instances that no longer exist are lost.
PRAGMA foreign_keys = OFF;
BEGIN;
CREATE TABLE roles_old (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    created_at   DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at   DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    name         TEXT NOT NULL UNIQUE,
    description  TEXT NOT NULL DEFAULT '',
    instance_id  INTEGER UNIQUE REFERENCES instances(id) ON DELETE CASCADE
);
INSERT INTO roles_old (id, created_at, updated_at, name, description, instance_id)
    SELECT r.id, r.created_at, r.updated_at, r.name, r.description, i.id
    FROM roles r LEFT JOIN instances i ON i.name = r.instance
    WHERE r.instance IS NULL OR i.id IS NOT NULL;
DELETE FROM sqlite_sequence WHERE name = 'roles_old';
INSERT INTO sqlite_sequence (name, seq)
    SELECT 'roles_old', seq FROM sqlite_sequence WHERE name = 'roles';
DROP TABLE roles;
ALTER TABLE roles_old RENAME TO roles;

CREATE TABLE role_instances_old (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    created_at   DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at   DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    role_id      INTEGER NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
    instance_id  INTEGER NOT NULL REFERENCES instances(id) ON DELETE CASCADE,
    UNIQUE (role_id, instance_id)
);
INSERT INTO role_instances_old (id, created_at, updated_at, role_id, instance_id)
    SELECT ri.id, ri.created_at, ri.updated_at, ri.role_id, i.id
    FROM role_instances ri JOIN instances i ON i.name = ri.instance;
DELETE FROM sqlite_sequence WHERE name = 'role_instances_old';
INSERT INTO sqlite_sequence (name, seq)
    SELECT 'role_instances_old', seq FROM sqlite_sequence WHERE name = 'role_instances';
DROP TABLE role_instances;
ALTER TABLE role_instances_old RENAME TO role_instances;
COMMIT;
PRAGMA foreign_keys = ON;
