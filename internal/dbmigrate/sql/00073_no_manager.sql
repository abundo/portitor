-- SPDX-FileCopyrightText: 2026 The Portitor contributors
-- SPDX-License-Identifier: AGPL-3.0-or-later

-- +goose Up
-- No more managers: every firewall's configuration is its own
-- portitor-config's. A firewall's config_url and config_fingerprint now
-- name its portitor-config for its HA peer, which needs no token.
ALTER TABLE users DROP COLUMN managed_by;
ALTER TABLE firewalls DROP COLUMN config_token;
UPDATE firewalls SET config_url = '', config_fingerprint = '';
ALTER TABLE ip_lists DROP COLUMN managed_by;
ALTER TABLE port_names DROP COLUMN managed_by;
ALTER TABLE services DROP COLUMN managed_by;
ALTER TABLE address_lists DROP COLUMN managed_by;
ALTER TABLE address_objects DROP COLUMN managed_by;
ALTER TABLE object_folders DROP COLUMN managed_by;
ALTER TABLE instances DROP COLUMN diverged;
ALTER TABLE instances DROP COLUMN managed_by;

-- +goose Down
ALTER TABLE instances ADD COLUMN managed_by TEXT NOT NULL DEFAULT '';
ALTER TABLE instances ADD COLUMN diverged BOOLEAN NOT NULL DEFAULT false;
ALTER TABLE object_folders ADD COLUMN managed_by TEXT NOT NULL DEFAULT '';
ALTER TABLE address_objects ADD COLUMN managed_by TEXT NOT NULL DEFAULT '';
ALTER TABLE address_lists ADD COLUMN managed_by TEXT NOT NULL DEFAULT '';
ALTER TABLE services ADD COLUMN managed_by TEXT NOT NULL DEFAULT '';
ALTER TABLE port_names ADD COLUMN managed_by TEXT NOT NULL DEFAULT '';
ALTER TABLE ip_lists ADD COLUMN managed_by TEXT NOT NULL DEFAULT '';
ALTER TABLE firewalls ADD COLUMN config_token TEXT NOT NULL DEFAULT '';
ALTER TABLE users ADD COLUMN managed_by TEXT NOT NULL DEFAULT '';
