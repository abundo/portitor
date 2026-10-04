-- SPDX-FileCopyrightText: 2026 The Portitor contributors
-- SPDX-License-Identifier: AGPL-3.0-or-later

-- +goose Up
-- SNMP (net-snmp's snmpd), read-only: whether the instance runs it, its
-- system location and contact, the client prefixes it answers, and its
-- SNMPv2c community (empty: none); the interfaces it answers on have
-- snmp_serve. SNMPv3 users are rows of snmp_users.
ALTER TABLE instances ADD COLUMN snmp_enabled BOOLEAN NOT NULL DEFAULT false;
ALTER TABLE instances ADD COLUMN snmp_location TEXT NOT NULL DEFAULT '';
ALTER TABLE instances ADD COLUMN snmp_contact TEXT NOT NULL DEFAULT '';
ALTER TABLE instances ADD COLUMN snmp_allow TEXT NOT NULL DEFAULT '[]';
ALTER TABLE instances ADD COLUMN snmp_community TEXT NOT NULL DEFAULT '';
ALTER TABLE interfaces ADD COLUMN snmp_serve BOOLEAN NOT NULL DEFAULT false;

CREATE TABLE snmp_users (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    created_at    DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at    DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    instance_id   INTEGER NOT NULL REFERENCES instances(id) ON DELETE CASCADE,
    name          TEXT NOT NULL,
    enabled       BOOLEAN NOT NULL DEFAULT true,
    description   TEXT NOT NULL DEFAULT '',
    auth_protocol TEXT NOT NULL DEFAULT 'SHA-256',
    auth_password TEXT NOT NULL DEFAULT '',
    priv_protocol TEXT NOT NULL DEFAULT 'AES',
    priv_password TEXT NOT NULL DEFAULT '',
    UNIQUE (instance_id, name)
);

-- +goose Down
DROP TABLE snmp_users;
ALTER TABLE interfaces DROP COLUMN snmp_serve;
ALTER TABLE instances DROP COLUMN snmp_community;
ALTER TABLE instances DROP COLUMN snmp_allow;
ALTER TABLE instances DROP COLUMN snmp_contact;
ALTER TABLE instances DROP COLUMN snmp_location;
ALTER TABLE instances DROP COLUMN snmp_enabled;
