-- SPDX-FileCopyrightText: 2026 The Portitor contributors
-- SPDX-License-Identifier: AGPL-3.0-or-later

-- +goose Up
-- Firewalls: the hosts portitor-web deploys to, each with its agent and
-- its generation (the agent's monotonic deploy id). The agent settings
-- move here from settings, whose generation becomes last_commit: a commit
-- deploys to one or more firewalls, and its number names the Revert
-- snapshot and the deployments it made (commit_id). Every instance and deployment is on one
-- firewall; firewall_id stays nullable only because SQLite can't add a
-- NOT NULL column with a foreign key, and portitor-web always sets it.
CREATE TABLE firewalls (
    id                INTEGER PRIMARY KEY AUTOINCREMENT,
    created_at        DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at        DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    name              TEXT NOT NULL UNIQUE,
    description       TEXT NOT NULL DEFAULT '',
    agent_url         TEXT NOT NULL DEFAULT '',
    agent_token       TEXT NOT NULL DEFAULT '',
    agent_fingerprint TEXT NOT NULL DEFAULT '',
    generation        INTEGER NOT NULL DEFAULT 0
);
INSERT INTO firewalls (id, name, agent_url, agent_token, agent_fingerprint, generation)
    SELECT 1, 'firewall', coalesce(agent_url, ''), coalesce(agent_token, ''), coalesce(agent_fingerprint, ''), coalesce(generation, 0)
    FROM settings WHERE id = 1;
INSERT OR IGNORE INTO firewalls (id, name) VALUES (1, 'firewall');

ALTER TABLE instances ADD COLUMN firewall_id INTEGER REFERENCES firewalls(id);
UPDATE instances SET firewall_id = 1;
CREATE INDEX instances_firewall ON instances (firewall_id);
-- Each firewall has one default instance: its host.
DROP INDEX instances_one_default;
CREATE UNIQUE INDEX instances_one_default ON instances (firewall_id) WHERE is_default;

-- Each firewall reports its own physical interfaces.
CREATE TABLE known_interfaces_new (
    firewall_id INTEGER NOT NULL REFERENCES firewalls(id) ON DELETE CASCADE,
    name        TEXT NOT NULL,
    created_at  DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (firewall_id, name)
);
INSERT INTO known_interfaces_new (firewall_id, name, created_at) SELECT 1, name, created_at FROM known_interfaces;
DROP TABLE known_interfaces;
ALTER TABLE known_interfaces_new RENAME TO known_interfaces;

-- A task runs on one firewall.
ALTER TABLE tasks ADD COLUMN firewall_id INTEGER REFERENCES firewalls(id) ON DELETE CASCADE;
UPDATE tasks SET firewall_id = 1;

ALTER TABLE deployments ADD COLUMN firewall_id INTEGER REFERENCES firewalls(id) ON DELETE CASCADE;
UPDATE deployments SET firewall_id = 1;
ALTER TABLE deployments ADD COLUMN commit_id INTEGER NOT NULL DEFAULT 0;
UPDATE deployments SET commit_id = generation;
ALTER TABLE settings RENAME COLUMN generation TO last_commit;

ALTER TABLE settings DROP COLUMN agent_url;
ALTER TABLE settings DROP COLUMN agent_token;
ALTER TABLE settings DROP COLUMN agent_fingerprint;

-- +goose Down
ALTER TABLE settings RENAME COLUMN last_commit TO generation;
ALTER TABLE deployments DROP COLUMN commit_id;
ALTER TABLE settings ADD COLUMN agent_url TEXT NOT NULL DEFAULT '';
ALTER TABLE settings ADD COLUMN agent_token TEXT NOT NULL DEFAULT '';
ALTER TABLE settings ADD COLUMN agent_fingerprint TEXT NOT NULL DEFAULT '';
UPDATE settings SET agent_url = f.agent_url, agent_token = f.agent_token, agent_fingerprint = f.agent_fingerprint
    FROM (SELECT * FROM firewalls WHERE id = 1) AS f WHERE settings.id = 1;
ALTER TABLE deployments DROP COLUMN firewall_id;
ALTER TABLE tasks DROP COLUMN firewall_id;
CREATE TABLE known_interfaces_old (
    name        TEXT PRIMARY KEY,
    created_at  DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);
INSERT OR IGNORE INTO known_interfaces_old (name, created_at) SELECT name, created_at FROM known_interfaces;
DROP TABLE known_interfaces;
ALTER TABLE known_interfaces_old RENAME TO known_interfaces;
DROP INDEX instances_one_default;
CREATE UNIQUE INDEX instances_one_default ON instances (is_default) WHERE is_default;
DROP INDEX instances_firewall;
ALTER TABLE instances DROP COLUMN firewall_id;
DROP TABLE firewalls;
