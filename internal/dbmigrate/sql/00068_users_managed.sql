-- SPDX-FileCopyrightText: 2026 The Portitor contributors
-- SPDX-License-Identifier: AGPL-3.0-or-later

-- +goose Up
-- portitor-config: a user its manager pushed is managed_by it, and changed
-- there only; local users stay this firewall's own.
ALTER TABLE users ADD COLUMN managed_by TEXT NOT NULL DEFAULT '';

-- +goose Down
ALTER TABLE users DROP COLUMN managed_by;
