-- SPDX-FileCopyrightText: 2026 The Portitor contributors
-- SPDX-License-Identifier: AGPL-3.0-or-later

-- +goose Up
-- Whether the instance translates its NAT64 prefix to IPv4 itself (Jool),
-- and the IPv4 prefixes it translates to; none uses the outgoing
-- interface's address.
ALTER TABLE instances ADD COLUMN nat64 BOOLEAN NOT NULL DEFAULT false;
ALTER TABLE instances ADD COLUMN nat64_pool4 TEXT NOT NULL DEFAULT '[]';

-- +goose Down
ALTER TABLE instances DROP COLUMN nat64_pool4;
ALTER TABLE instances DROP COLUMN nat64;
