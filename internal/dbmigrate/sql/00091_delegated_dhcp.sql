-- SPDX-FileCopyrightText: 2026 The Portitor contributors
-- SPDX-License-Identifier: AGPL-3.0-or-later

-- +goose Up
-- DHCPv6 and SLAAC on an interface's addresses in a delegated prefix
-- (<wan0>:2000::1/64): the range is host parts, the low 64 bits.
ALTER TABLE interfaces ADD COLUMN delegated_dhcp BOOLEAN NOT NULL DEFAULT false;
ALTER TABLE interfaces ADD COLUMN delegated_range_start TEXT NOT NULL DEFAULT '';
ALTER TABLE interfaces ADD COLUMN delegated_range_end TEXT NOT NULL DEFAULT '';
ALTER TABLE interfaces ADD COLUMN delegated_slaac BOOLEAN NOT NULL DEFAULT true;

-- +goose Down
ALTER TABLE interfaces DROP COLUMN delegated_dhcp;
ALTER TABLE interfaces DROP COLUMN delegated_range_start;
ALTER TABLE interfaces DROP COLUMN delegated_range_end;
ALTER TABLE interfaces DROP COLUMN delegated_slaac;
