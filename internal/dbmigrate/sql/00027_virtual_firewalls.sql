-- SPDX-FileCopyrightText: 2026 The Portitor contributors
-- SPDX-License-Identifier: AGPL-3.0-or-later

-- +goose Up
-- Virtual firewalls (more than one instance) and links are turned on under
-- Settings; on for a database that already uses them.
ALTER TABLE settings ADD COLUMN virtual_firewalls BOOLEAN NOT NULL DEFAULT false;
UPDATE settings SET virtual_firewalls = true
WHERE (SELECT count(*) FROM instances) > 1 OR EXISTS (SELECT 1 FROM links);

-- +goose Down
ALTER TABLE settings DROP COLUMN virtual_firewalls;
