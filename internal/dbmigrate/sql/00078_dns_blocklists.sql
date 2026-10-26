-- SPDX-FileCopyrightText: 2026 The Portitor contributors
-- SPDX-License-Identifier: AGPL-3.0-or-later

-- +goose Up
-- DNS blocklists: response policy zones the agent downloads
-- (fwconfig.DNSBlocklist), and the domains none of them blocks.
CREATE TABLE dns_blocklists (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    created_at  DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at  DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    instance_id INTEGER NOT NULL REFERENCES instances(id) ON DELETE CASCADE,
    name        TEXT NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    enabled     BOOLEAN NOT NULL DEFAULT true,
    urls        TEXT NOT NULL DEFAULT '[]',
    auth_key    TEXT NOT NULL DEFAULT '',
    action      TEXT NOT NULL DEFAULT 'nxdomain',
    refresh     INTEGER NOT NULL DEFAULT 720,
    UNIQUE (instance_id, name)
);
ALTER TABLE instances ADD COLUMN dns_blocklist_allow TEXT NOT NULL DEFAULT '[]';

-- +goose Down
ALTER TABLE instances DROP COLUMN dns_blocklist_allow;
DROP TABLE dns_blocklists;
