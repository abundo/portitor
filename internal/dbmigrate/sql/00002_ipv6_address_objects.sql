-- SPDX-FileCopyrightText: 2026 The Portitor contributors
-- SPDX-License-Identifier: AGPL-3.0-or-later

-- +goose Up
-- Named hosts and prefixes, usable by name wherever an address list is
-- entered (rules, NAT, routes, DNS, WireGuard, DHCP). A host is an object
-- whose entries are all single addresses.
CREATE TABLE address_objects (
    id          BIGSERIAL PRIMARY KEY,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    name        TEXT NOT NULL UNIQUE,
    addresses   JSONB NOT NULL DEFAULT '[]',
    description TEXT NOT NULL DEFAULT ''
);

-- IPv6 router advertisements per IPAM prefix; ra_slaac sets the
-- autonomous flag (clients pick their own address, /64 only).
ALTER TABLE ipam_prefixes ADD COLUMN ra_enabled BOOLEAN NOT NULL DEFAULT false;
ALTER TABLE ipam_prefixes ADD COLUMN ra_slaac BOOLEAN NOT NULL DEFAULT false;

-- +goose Down
ALTER TABLE ipam_prefixes DROP COLUMN ra_slaac;
ALTER TABLE ipam_prefixes DROP COLUMN ra_enabled;
DROP TABLE address_objects;
