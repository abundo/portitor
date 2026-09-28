-- SPDX-FileCopyrightText: 2026 The Portitor contributors
-- SPDX-License-Identifier: AGPL-3.0-or-later

-- +goose Up
-- ICMP/ICMPv6 types a rule with protocol icmp or icmpv6 matches.
ALTER TABLE rules ADD COLUMN icmp_types TEXT NOT NULL DEFAULT '[]';

-- +goose Down
ALTER TABLE rules DROP COLUMN icmp_types;
