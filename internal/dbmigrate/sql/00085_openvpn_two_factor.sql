-- SPDX-FileCopyrightText: 2026 The Portitor contributors
-- SPDX-License-Identifier: AGPL-3.0-or-later

-- +goose Up
-- An OpenVPN server's two-factor login (fwconfig.OpenVPN.TwoFactor): ''
-- off, 'user' a TOTP code from the users with two-factor login on,
-- 'required' from everyone.
ALTER TABLE interfaces ADD COLUMN ovpn_two_factor TEXT NOT NULL DEFAULT '';

-- +goose Down
ALTER TABLE interfaces DROP COLUMN ovpn_two_factor;
