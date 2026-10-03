-- SPDX-FileCopyrightText: 2026 The Portitor contributors
-- SPDX-License-Identifier: AGPL-3.0-or-later

-- +goose NO TRANSACTION
-- +goose Up
-- SOA templates, DNSSEC policies and DNS templates belong to an instance.
-- One of the default instance may be global: the other instances use it,
-- read-only. The existing ones, shared until now, move to the default
-- instance as global ones. Names are unique per instance (and a global
-- name across all, checked by portitor-web). The tables are rebuilt,
-- keeping their AUTOINCREMENT counters.
PRAGMA foreign_keys = OFF;
BEGIN;
CREATE TABLE dns_soa_templates_new (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    created_at  DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at  DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    instance_id INTEGER NOT NULL REFERENCES instances(id) ON DELETE CASCADE,
    global      BOOLEAN NOT NULL DEFAULT false,
    name        TEXT NOT NULL,
    mname       TEXT NOT NULL,
    rname       TEXT NOT NULL,
    refresh     INTEGER NOT NULL DEFAULT 86400,
    retry       INTEGER NOT NULL DEFAULT 7200,
    expire      INTEGER NOT NULL DEFAULT 3600000,
    minimum     INTEGER NOT NULL DEFAULT 3600,
    UNIQUE (instance_id, name)
);
INSERT INTO dns_soa_templates_new (id, created_at, updated_at, instance_id, global, name, mname, rname, refresh, retry, expire, minimum)
    SELECT id, created_at, updated_at, COALESCE((SELECT id FROM instances WHERE is_default), (SELECT min(id) FROM instances)), true, name, mname, rname, refresh, retry, expire, minimum
    FROM dns_soa_templates;
DELETE FROM sqlite_sequence WHERE name = 'dns_soa_templates_new';
INSERT INTO sqlite_sequence (name, seq)
    SELECT 'dns_soa_templates_new', seq FROM sqlite_sequence WHERE name = 'dns_soa_templates';
DROP TABLE dns_soa_templates;
ALTER TABLE dns_soa_templates_new RENAME TO dns_soa_templates;

CREATE TABLE dns_dnssec_policies_new (
    id                         INTEGER PRIMARY KEY AUTOINCREMENT,
    created_at                 DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at                 DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    instance_id                INTEGER NOT NULL REFERENCES instances(id) ON DELETE CASCADE,
    global                     BOOLEAN NOT NULL DEFAULT false,
    name                       TEXT NOT NULL,
    ksk_lifetime               TEXT NOT NULL DEFAULT '',
    ksk_algorithm              TEXT NOT NULL,
    zsk_lifetime               TEXT NOT NULL DEFAULT '',
    zsk_algorithm              TEXT NOT NULL,
    purge_keys                 TEXT NOT NULL DEFAULT '',
    signatures_validity        TEXT NOT NULL DEFAULT '',
    signatures_validity_dnskey TEXT NOT NULL DEFAULT '',
    signatures_refresh         TEXT NOT NULL DEFAULT '',
    UNIQUE (instance_id, name)
);
INSERT INTO dns_dnssec_policies_new (id, created_at, updated_at, instance_id, global, name, ksk_lifetime, ksk_algorithm,
        zsk_lifetime, zsk_algorithm, purge_keys, signatures_validity, signatures_validity_dnskey, signatures_refresh)
    SELECT id, created_at, updated_at, COALESCE((SELECT id FROM instances WHERE is_default), (SELECT min(id) FROM instances)), true, name, ksk_lifetime, ksk_algorithm,
        zsk_lifetime, zsk_algorithm, purge_keys, signatures_validity, signatures_validity_dnskey, signatures_refresh
    FROM dns_dnssec_policies;
DELETE FROM sqlite_sequence WHERE name = 'dns_dnssec_policies_new';
INSERT INTO sqlite_sequence (name, seq)
    SELECT 'dns_dnssec_policies_new', seq FROM sqlite_sequence WHERE name = 'dns_dnssec_policies';
DROP TABLE dns_dnssec_policies;
ALTER TABLE dns_dnssec_policies_new RENAME TO dns_dnssec_policies;

CREATE TABLE dns_templates_new (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    created_at       DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at       DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    instance_id      INTEGER NOT NULL REFERENCES instances(id) ON DELETE CASCADE,
    global           BOOLEAN NOT NULL DEFAULT false,
    name             TEXT NOT NULL,
    soa_template_id  INTEGER NOT NULL REFERENCES dns_soa_templates(id) ON DELETE RESTRICT,
    default_ttl      INTEGER NOT NULL DEFAULT 3600,
    dnssec_policy_id INTEGER REFERENCES dns_dnssec_policies(id) ON DELETE RESTRICT,
    nameservers      TEXT NOT NULL DEFAULT '[]',
    description      TEXT NOT NULL DEFAULT '',
    UNIQUE (instance_id, name)
);
INSERT INTO dns_templates_new (id, created_at, updated_at, instance_id, global, name, soa_template_id, default_ttl,
        dnssec_policy_id, nameservers, description)
    SELECT id, created_at, updated_at, COALESCE((SELECT id FROM instances WHERE is_default), (SELECT min(id) FROM instances)), true, name, soa_template_id, default_ttl,
        dnssec_policy_id, nameservers, description
    FROM dns_templates;
DELETE FROM sqlite_sequence WHERE name = 'dns_templates_new';
INSERT INTO sqlite_sequence (name, seq)
    SELECT 'dns_templates_new', seq FROM sqlite_sequence WHERE name = 'dns_templates';
DROP TABLE dns_templates;
ALTER TABLE dns_templates_new RENAME TO dns_templates;
COMMIT;
PRAGMA foreign_keys = ON;

-- +goose Down
-- The instances' own templates could clash by name once shared again.
SELECT 1;
