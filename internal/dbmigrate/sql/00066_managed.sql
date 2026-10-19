-- SPDX-FileCopyrightText: 2026 The Portitor contributors
-- SPDX-License-Identifier: AGPL-3.0-or-later

-- +goose Up
-- portitor-config (the local mode): an instance or shared object a manager
-- pushed is managed_by it and read-only here, unless the instance is
-- diverged (break-glass: edited here since).
ALTER TABLE instances ADD COLUMN managed_by TEXT NOT NULL DEFAULT '';
ALTER TABLE instances ADD COLUMN diverged BOOLEAN NOT NULL DEFAULT false;
ALTER TABLE object_folders ADD COLUMN managed_by TEXT NOT NULL DEFAULT '';
ALTER TABLE address_objects ADD COLUMN managed_by TEXT NOT NULL DEFAULT '';
ALTER TABLE address_lists ADD COLUMN managed_by TEXT NOT NULL DEFAULT '';
ALTER TABLE services ADD COLUMN managed_by TEXT NOT NULL DEFAULT '';
ALTER TABLE port_names ADD COLUMN managed_by TEXT NOT NULL DEFAULT '';
ALTER TABLE ip_lists ADD COLUMN managed_by TEXT NOT NULL DEFAULT '';

-- +goose Down
ALTER TABLE ip_lists DROP COLUMN managed_by;
ALTER TABLE port_names DROP COLUMN managed_by;
ALTER TABLE services DROP COLUMN managed_by;
ALTER TABLE address_lists DROP COLUMN managed_by;
ALTER TABLE address_objects DROP COLUMN managed_by;
ALTER TABLE object_folders DROP COLUMN managed_by;
ALTER TABLE instances DROP COLUMN diverged;
ALTER TABLE instances DROP COLUMN managed_by;
