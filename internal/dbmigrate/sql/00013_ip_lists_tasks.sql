-- SPDX-FileCopyrightText: 2026 The Portitor contributors
-- SPDX-License-Identifier: AGPL-3.0-or-later

-- +goose Up
-- IP lists the agent downloads (CrowdSec decisions, or a plain-text list
-- such as a CrowdSec blocklist integration). Rules refer to one as
-- "@name" in their address lists.
CREATE TABLE ip_lists (
    id          BIGSERIAL PRIMARY KEY,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    name        TEXT NOT NULL UNIQUE,
    description TEXT NOT NULL DEFAULT '',
    source      TEXT NOT NULL,
    url         TEXT NOT NULL,
    username    TEXT NOT NULL DEFAULT '',
    password    TEXT NOT NULL DEFAULT '',
    api_key     TEXT NOT NULL DEFAULT ''
);

-- Tasks the agent runs on a cron schedule: download an IP list, or run a
-- command as the agent's console user. Deleting a list a task downloads
-- is refused.
CREATE TABLE tasks (
    id          BIGSERIAL PRIMARY KEY,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    name        TEXT NOT NULL UNIQUE,
    description TEXT NOT NULL DEFAULT '',
    enabled     BOOLEAN NOT NULL DEFAULT true,
    schedule    TEXT NOT NULL,
    kind        TEXT NOT NULL,
    ip_list_id  BIGINT REFERENCES ip_lists(id),
    command     TEXT NOT NULL DEFAULT '',
    timeout     INTEGER NOT NULL DEFAULT 0
);

-- +goose Down
DROP TABLE tasks;
DROP TABLE ip_lists;
