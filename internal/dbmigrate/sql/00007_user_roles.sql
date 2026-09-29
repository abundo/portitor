-- SPDX-FileCopyrightText: 2026 The Portitor contributors
-- SPDX-License-Identifier: AGPL-3.0-or-later

-- +goose Up
-- A user is an admin (everything) or a viewer (reads the configuration and
-- status, changes nothing but their own profile). Existing users stay admins.
ALTER TABLE users ADD COLUMN role TEXT NOT NULL DEFAULT 'admin' CHECK (role IN ('admin', 'viewer'));

-- +goose Down
ALTER TABLE users DROP COLUMN role;
