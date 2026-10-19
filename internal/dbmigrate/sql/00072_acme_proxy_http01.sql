-- SPDX-FileCopyrightText: 2026 The Portitor contributors
-- SPDX-License-Identifier: AGPL-3.0-or-later

-- +goose NO TRANSACTION
-- +goose Up
-- ACME proxy policies may get the certificates upstream by HTTP-01
-- (challenge), answered by the firewall on port 80 of interface_id, instead
-- of DNS-01 through dyndns_client_id. The table is rebuilt to make
-- dyndns_client_id nullable, keeping its AUTOINCREMENT counter.
PRAGMA foreign_keys = OFF;
BEGIN;
CREATE TABLE acme_proxy_policies_new (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    created_at       DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at       DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    instance_id      INTEGER NOT NULL REFERENCES instances(id) ON DELETE CASCADE,
    name             TEXT NOT NULL,
    enabled          BOOLEAN NOT NULL DEFAULT true,
    description      TEXT NOT NULL DEFAULT '',
    domains          TEXT NOT NULL DEFAULT '[]',
    sources          TEXT NOT NULL DEFAULT '[]',
    challenge        TEXT NOT NULL DEFAULT 'dns-01',
    interface_id     INTEGER REFERENCES interfaces(id),
    dyndns_client_id INTEGER REFERENCES dyndns_clients(id),
    UNIQUE (instance_id, name)
);
INSERT INTO acme_proxy_policies_new (id, created_at, updated_at, instance_id, name, enabled, description,
        domains, sources, dyndns_client_id)
    SELECT id, created_at, updated_at, instance_id, name, enabled, description,
        domains, sources, dyndns_client_id
    FROM acme_proxy_policies;
DELETE FROM sqlite_sequence WHERE name = 'acme_proxy_policies_new';
INSERT INTO sqlite_sequence (name, seq)
    SELECT 'acme_proxy_policies_new', seq FROM sqlite_sequence WHERE name = 'acme_proxy_policies';
DROP TABLE acme_proxy_policies;
ALTER TABLE acme_proxy_policies_new RENAME TO acme_proxy_policies;
COMMIT;
PRAGMA foreign_keys = ON;

-- +goose Down
-- HTTP-01 policies have no DNS update client.
SELECT 1;
