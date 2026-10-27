-- SPDX-FileCopyrightText: 2026 The Portitor contributors
-- SPDX-License-Identifier: AGPL-3.0-or-later

-- +goose Up
-- Remote syslog servers rsyslog sends the host's journal to: the default
-- instance's alone (the journal is the host's). Disabled, a server is left
-- out.
CREATE TABLE syslog_servers (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    created_at  DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at  DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    instance_id INTEGER NOT NULL REFERENCES instances(id) ON DELETE CASCADE,
    enabled     BOOLEAN NOT NULL DEFAULT true,
    description TEXT NOT NULL DEFAULT '',
    address     TEXT NOT NULL,
    port        INTEGER NOT NULL DEFAULT 514,
    protocol    TEXT NOT NULL DEFAULT 'udp',
    format      TEXT NOT NULL DEFAULT 'rfc3164',
    severity    TEXT NOT NULL DEFAULT 'info',
    UNIQUE (instance_id, address, port, protocol)
);

-- +goose Down
DROP TABLE syslog_servers;
