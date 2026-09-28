-- SPDX-FileCopyrightText: 2026 The Portitor contributors
-- SPDX-License-Identifier: AGPL-3.0-or-later

-- +goose Up
-- Services become protocol matches that rules name in their services list,
-- in place of the rule's own protocol, ports and ICMP types. The old custom
-- services (port names) are dropped, not converted.
DROP TABLE services;
CREATE TABLE services (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    created_at  DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at  DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    name        TEXT NOT NULL UNIQUE,
    description TEXT NOT NULL DEFAULT '',
    -- 'tcp/udp/sctp' (ports), 'icmp', 'icmp6' (icmp_type, icmp_code) or
    -- 'ip' (ip_protocol).
    type        TEXT NOT NULL,
    -- JSON array of { protocol, dst_lo, dst_hi, src_lo, src_hi }.
    ports       TEXT NOT NULL DEFAULT '[]',
    icmp_type   TEXT NOT NULL DEFAULT '',
    icmp_code   INTEGER,
    ip_protocol INTEGER NOT NULL DEFAULT 0
);
ALTER TABLE rules DROP COLUMN protocol;
ALTER TABLE rules DROP COLUMN dst_ports;
ALTER TABLE rules DROP COLUMN icmp_types;
ALTER TABLE rules ADD COLUMN services TEXT NOT NULL DEFAULT '[]';

-- +goose Down
ALTER TABLE rules DROP COLUMN services;
ALTER TABLE rules ADD COLUMN icmp_types TEXT NOT NULL DEFAULT '[]';
ALTER TABLE rules ADD COLUMN dst_ports TEXT NOT NULL DEFAULT '';
ALTER TABLE rules ADD COLUMN protocol TEXT NOT NULL DEFAULT '';
DROP TABLE services;
CREATE TABLE services (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    created_at  DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at  DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    name        TEXT NOT NULL UNIQUE,
    ports       TEXT NOT NULL,
    description TEXT NOT NULL DEFAULT ''
);
