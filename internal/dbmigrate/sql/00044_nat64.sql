-- SPDX-FileCopyrightText: 2026 The Portitor contributors
-- SPDX-License-Identifier: AGPL-3.0-or-later

-- +goose Up
-- The instance's NAT64 prefix, and whether its DNS server synthesizes
-- AAAA records in it (DNS64).
ALTER TABLE instances ADD COLUMN nat64_prefix TEXT NOT NULL DEFAULT '64:ff9b::/96';
ALTER TABLE instances ADD COLUMN dns64 BOOLEAN NOT NULL DEFAULT false;
-- Whether an interface's router advertisements announce the NAT64 prefix
-- (PREF64), for 464XLAT clients.
ALTER TABLE interfaces ADD COLUMN xlat464 BOOLEAN NOT NULL DEFAULT false;

-- +goose Down
ALTER TABLE interfaces DROP COLUMN xlat464;
ALTER TABLE instances DROP COLUMN dns64;
ALTER TABLE instances DROP COLUMN nat64_prefix;
