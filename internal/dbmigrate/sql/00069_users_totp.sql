-- SPDX-FileCopyrightText: 2026 The Portitor contributors
-- SPDX-License-Identifier: AGPL-3.0-or-later

-- +goose Up
-- Two-factor login with TOTP (RFC 6238): the secret (base32), on once a
-- code from it was checked; the secret being set up; the last time step
-- used (no code twice); the unused recovery codes' SHA-256 hashes (JSON).
ALTER TABLE users ADD COLUMN totp_secret TEXT NOT NULL DEFAULT '';
ALTER TABLE users ADD COLUMN totp_pending TEXT NOT NULL DEFAULT '';
ALTER TABLE users ADD COLUMN totp_last_step INTEGER NOT NULL DEFAULT 0;
ALTER TABLE users ADD COLUMN recovery_codes TEXT NOT NULL DEFAULT '';

-- +goose Down
ALTER TABLE users DROP COLUMN recovery_codes;
ALTER TABLE users DROP COLUMN totp_last_step;
ALTER TABLE users DROP COLUMN totp_pending;
ALTER TABLE users DROP COLUMN totp_secret;
