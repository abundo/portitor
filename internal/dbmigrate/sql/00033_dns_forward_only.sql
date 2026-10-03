-- SPDX-FileCopyrightText: 2026 The Portitor contributors
-- SPDX-License-Identifier: AGPL-3.0-or-later

-- +goose Up
-- Forward-only zones: the DNS servers BIND forwards the zone's queries to
-- (a JSON array of addresses or named hosts).
ALTER TABLE dns_zones ADD COLUMN forwarders TEXT NOT NULL DEFAULT '[]';

-- +goose Down
ALTER TABLE dns_zones DROP COLUMN forwarders;
