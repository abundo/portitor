-- SPDX-FileCopyrightText: 2026 The Portitor contributors
-- SPDX-License-Identifier: AGPL-3.0-or-later

-- +goose Up
-- Dynamic DNS clients: RFC 2136 updates of records on an external
-- nameserver, following an interface's addresses. Deleting an interface
-- a client uses is refused (NO ACTION, checked at the end of the
-- statement, so deleting the whole instance still works).
CREATE TABLE dyndns_clients (
    id              BIGSERIAL PRIMARY KEY,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    instance_id     BIGINT NOT NULL REFERENCES instances(id) ON DELETE CASCADE,
    name            TEXT NOT NULL,
    description     TEXT NOT NULL DEFAULT '',
    enabled         BOOLEAN NOT NULL DEFAULT true,
    interface_id    BIGINT NOT NULL REFERENCES interfaces(id),
    server          TEXT NOT NULL,
    zone            TEXT NOT NULL,
    tsig_name       TEXT NOT NULL DEFAULT '',
    tsig_algorithm  TEXT NOT NULL DEFAULT '',
    tsig_secret     TEXT NOT NULL DEFAULT '',
    retry_interval  INTEGER NOT NULL DEFAULT 0,
    verify_interval INTEGER NOT NULL DEFAULT 0,
    UNIQUE (instance_id, name)
);

CREATE TABLE dyndns_records (
    id          BIGSERIAL PRIMARY KEY,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    client_id   BIGINT NOT NULL REFERENCES dyndns_clients(id) ON DELETE CASCADE,
    name        TEXT NOT NULL,
    type        TEXT NOT NULL,
    ttl         INTEGER NOT NULL DEFAULT 0,
    value       TEXT NOT NULL DEFAULT '',
    description TEXT NOT NULL DEFAULT ''
);

-- +goose Down
DROP TABLE dyndns_records;
DROP TABLE dyndns_clients;
