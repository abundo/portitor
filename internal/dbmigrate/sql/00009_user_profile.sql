-- SPDX-FileCopyrightText: 2026 The Portitor contributors
-- SPDX-License-Identifier: AGPL-3.0-or-later

-- +goose Up
-- Profile data the user edits on their own settings page.
ALTER TABLE users ADD COLUMN full_name TEXT NOT NULL DEFAULT '';
ALTER TABLE users ADD COLUMN email TEXT NOT NULL DEFAULT '';

-- +goose Down
ALTER TABLE users DROP COLUMN email;
ALTER TABLE users DROP COLUMN full_name;
