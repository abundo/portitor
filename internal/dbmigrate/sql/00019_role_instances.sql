-- SPDX-FileCopyrightText: 2026 The Portitor contributors
-- SPDX-License-Identifier: AGPL-3.0-or-later

-- +goose Up
-- The instances a role made by hand grants its members (at their level).
-- An instance's own role grants just that instance (roles.instance_id).
CREATE TABLE role_instances (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    created_at   DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at   DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    role_id      INTEGER NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
    instance_id  INTEGER NOT NULL REFERENCES instances(id) ON DELETE CASCADE,
    UNIQUE (role_id, instance_id)
);
-- The instances a deployment built from the database; empty: all of them.
ALTER TABLE deployments ADD COLUMN instances TEXT NOT NULL DEFAULT '[]';

-- +goose Down
ALTER TABLE deployments DROP COLUMN instances;
DROP TABLE role_instances;
