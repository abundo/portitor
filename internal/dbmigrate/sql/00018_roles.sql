-- SPDX-FileCopyrightText: 2026 The Portitor contributors
-- SPDX-License-Identifier: AGPL-3.0-or-later

-- +goose Up
-- Roles group users. A role with an instance_id belongs to that instance:
-- portitor-web creates, renames and removes it with the instance. Each
-- member is an admin or a viewer in the role.
CREATE TABLE roles (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    created_at   DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at   DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    name         TEXT NOT NULL UNIQUE,
    description  TEXT NOT NULL DEFAULT '',
    instance_id  INTEGER UNIQUE REFERENCES instances(id) ON DELETE CASCADE
);
CREATE TABLE role_members (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    created_at  DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at  DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    role_id     INTEGER NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
    user_id     INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    level       TEXT NOT NULL DEFAULT 'viewer',
    UNIQUE (role_id, user_id)
);
INSERT INTO roles (name, description, instance_id)
    SELECT 'instance-' || name, 'Users of instance ' || name, id FROM instances;

-- +goose Down
DROP TABLE role_members;
DROP TABLE roles;
