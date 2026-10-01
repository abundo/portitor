-- SPDX-FileCopyrightText: 2026 The Portitor contributors
-- SPDX-License-Identifier: AGPL-3.0-or-later

-- +goose Up
-- A DHCPv6 client on the interface; dhcpv6_pd also asks for a delegated
-- prefix, of dhcpv6_pd_length bits (0: the server chooses).
ALTER TABLE interfaces ADD COLUMN dhcpv6 BOOLEAN NOT NULL DEFAULT false;
ALTER TABLE interfaces ADD COLUMN dhcpv6_pd BOOLEAN NOT NULL DEFAULT false;
ALTER TABLE interfaces ADD COLUMN dhcpv6_pd_length INTEGER NOT NULL DEFAULT 0;

-- +goose Down
ALTER TABLE interfaces DROP COLUMN dhcpv6_pd_length;
ALTER TABLE interfaces DROP COLUMN dhcpv6_pd;
ALTER TABLE interfaces DROP COLUMN dhcpv6;
