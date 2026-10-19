-- SPDX-FileCopyrightText: 2026 The Portitor contributors
-- SPDX-License-Identifier: AGPL-3.0-or-later

-- +goose Up
-- A user with totp_required must set up two-factor login before anything
-- else; new users get settings.totp_default.
ALTER TABLE users ADD COLUMN totp_required BOOLEAN NOT NULL DEFAULT false;
ALTER TABLE settings ADD COLUMN totp_default BOOLEAN NOT NULL DEFAULT false;

-- +goose Down
ALTER TABLE settings DROP COLUMN totp_default;
ALTER TABLE users DROP COLUMN totp_required;
