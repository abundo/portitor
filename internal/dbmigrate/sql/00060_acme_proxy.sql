-- SPDX-FileCopyrightText: 2026 The Portitor contributors
-- SPDX-License-Identifier: AGPL-3.0-or-later

-- +goose Up
-- The ACME proxy: an ACME server for the hosts behind the firewall, on
-- acme_proxy_port of the interfaces with acme_proxy_serve, presenting
-- acme_proxy_certificate_id (a self-signed one when NULL), getting the
-- certificates from acme_proxy_ca by DNS-01. Its policies allow names
-- (domains, a JSON array) from source prefixes (sources), each with the
-- DNS update client whose provider writes the TXT records.
ALTER TABLE instances ADD COLUMN acme_proxy_enabled BOOLEAN NOT NULL DEFAULT false;
ALTER TABLE instances ADD COLUMN acme_proxy_port INTEGER NOT NULL DEFAULT 8555;
ALTER TABLE instances ADD COLUMN acme_proxy_ca TEXT NOT NULL DEFAULT 'letsencrypt';
ALTER TABLE instances ADD COLUMN acme_proxy_email TEXT NOT NULL DEFAULT '';
ALTER TABLE instances ADD COLUMN acme_proxy_certificate_id INTEGER REFERENCES certificates(id) ON DELETE SET NULL;
ALTER TABLE interfaces ADD COLUMN acme_proxy_serve BOOLEAN NOT NULL DEFAULT false;

CREATE TABLE acme_proxy_policies (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    created_at       DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at       DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    instance_id      INTEGER NOT NULL REFERENCES instances(id) ON DELETE CASCADE,
    name             TEXT NOT NULL,
    enabled          BOOLEAN NOT NULL DEFAULT true,
    description      TEXT NOT NULL DEFAULT '',
    domains          TEXT NOT NULL DEFAULT '[]',
    sources          TEXT NOT NULL DEFAULT '[]',
    dyndns_client_id INTEGER NOT NULL REFERENCES dyndns_clients(id),
    UNIQUE (instance_id, name)
);

-- +goose Down
DROP TABLE acme_proxy_policies;
ALTER TABLE interfaces DROP COLUMN acme_proxy_serve;
ALTER TABLE instances DROP COLUMN acme_proxy_certificate_id;
ALTER TABLE instances DROP COLUMN acme_proxy_email;
ALTER TABLE instances DROP COLUMN acme_proxy_ca;
ALTER TABLE instances DROP COLUMN acme_proxy_port;
ALTER TABLE instances DROP COLUMN acme_proxy_enabled;
