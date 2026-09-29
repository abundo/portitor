-- SPDX-FileCopyrightText: 2026 The Portitor contributors
-- SPDX-License-Identifier: AGPL-3.0-or-later

-- +goose Up
-- Folders that structure the named hosts (kind 'hosts') and the IP lists
-- (kind 'ip_lists') in the GUI. They nest, and mean nothing to the
-- firewall. Deleting a folder that holds anything is refused.
CREATE TABLE object_folders (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    created_at  DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at  DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    kind        TEXT NOT NULL,
    parent_id   INTEGER REFERENCES object_folders(id),
    name        TEXT NOT NULL
);
ALTER TABLE address_objects ADD COLUMN folder_id INTEGER REFERENCES object_folders(id);
ALTER TABLE ip_lists ADD COLUMN folder_id INTEGER REFERENCES object_folders(id);

-- +goose Down
ALTER TABLE ip_lists DROP COLUMN folder_id;
ALTER TABLE address_objects DROP COLUMN folder_id;
DROP TABLE object_folders;
