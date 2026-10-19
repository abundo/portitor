-- SPDX-FileCopyrightText: 2026 The Portitor contributors
-- SPDX-License-Identifier: AGPL-3.0-or-later

-- +goose Up
-- A firewall with portitor-config: the manager pushes its virtual
-- firewalls there (manager API, its token and certificate pin) and commits
-- through it; the agent is asked for live data only.
ALTER TABLE firewalls ADD COLUMN config_url TEXT NOT NULL DEFAULT '';
ALTER TABLE firewalls ADD COLUMN config_token TEXT NOT NULL DEFAULT '';
ALTER TABLE firewalls ADD COLUMN config_fingerprint TEXT NOT NULL DEFAULT '';

-- +goose Down
ALTER TABLE firewalls DROP COLUMN config_fingerprint;
ALTER TABLE firewalls DROP COLUMN config_token;
ALTER TABLE firewalls DROP COLUMN config_url;
