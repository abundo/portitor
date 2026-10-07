-- SPDX-FileCopyrightText: 2026 The Portitor contributors
-- SPDX-License-Identifier: AGPL-3.0-or-later

-- +goose NO TRANSACTION
-- +goose Up
-- VRFs become their own table (Routing → VRF) instead of interfaces of kind
-- vrf (migration 52): each such interface becomes a VRF of the same name,
-- table and description, its members are put in it (interfaces.vrf), and
-- the routes' vrf_id refers to the VRF. SQLite cannot change a column's
-- foreign key, so routes is rebuilt, keeping its AUTOINCREMENT counter.
PRAGMA foreign_keys = OFF;
BEGIN;
CREATE TABLE vrfs (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    created_at  DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at  DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    instance_id INTEGER NOT NULL REFERENCES instances(id) ON DELETE CASCADE,
    name        TEXT NOT NULL,
    route_table INTEGER NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    UNIQUE (instance_id, name),
    UNIQUE (instance_id, route_table)
);
INSERT INTO vrfs (instance_id, name, route_table, description)
    SELECT instance_id, name, vrf_table, description FROM interfaces WHERE kind = 'vrf';
ALTER TABLE interfaces ADD COLUMN vrf TEXT NOT NULL DEFAULT '';
UPDATE interfaces SET vrf = (
    SELECT v.name FROM interfaces v, json_each(v.members) m
    WHERE v.kind = 'vrf' AND v.instance_id = interfaces.instance_id AND m.value = interfaces.name
    LIMIT 1
) WHERE kind <> 'vrf' AND EXISTS (
    SELECT 1 FROM interfaces v, json_each(v.members) m
    WHERE v.kind = 'vrf' AND v.instance_id = interfaces.instance_id AND m.value = interfaces.name
);

CREATE TABLE routes_new (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    created_at   DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at   DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    instance_id  INTEGER NOT NULL REFERENCES instances(id) ON DELETE CASCADE,
    destination  TEXT NOT NULL,
    gateway      TEXT NOT NULL DEFAULT '',
    interface_id INTEGER REFERENCES interfaces(id) ON DELETE CASCADE,
    metric       INTEGER NOT NULL DEFAULT 0,
    enabled      BOOLEAN NOT NULL DEFAULT true,
    description  TEXT NOT NULL DEFAULT '',
    bfd          BOOLEAN NOT NULL DEFAULT false,
    vrf_id       INTEGER REFERENCES vrfs(id)
);
-- A route through a vrf interface itself loses that interface.
INSERT INTO routes_new (id, created_at, updated_at, instance_id, destination, gateway, interface_id, metric, enabled, description, bfd, vrf_id)
    SELECT r.id, r.created_at, r.updated_at, r.instance_id, r.destination, r.gateway,
        (SELECT i.id FROM interfaces i WHERE i.id = r.interface_id AND i.kind <> 'vrf'),
        r.metric, r.enabled, r.description, r.bfd,
        (SELECT v.id FROM vrfs v JOIN interfaces i ON i.instance_id = v.instance_id AND i.name = v.name WHERE i.id = r.vrf_id)
    FROM routes r;
DELETE FROM routes_new WHERE gateway = '' AND interface_id IS NULL;
DELETE FROM sqlite_sequence WHERE name = 'routes_new';
INSERT INTO sqlite_sequence (name, seq)
    SELECT 'routes_new', seq FROM sqlite_sequence WHERE name = 'routes';
DROP TABLE routes;
ALTER TABLE routes_new RENAME TO routes;

DELETE FROM interfaces WHERE kind = 'vrf';
ALTER TABLE interfaces DROP COLUMN vrf_table;
COMMIT;
PRAGMA foreign_keys = ON;

-- +goose Down
ALTER TABLE interfaces ADD COLUMN vrf_table INTEGER NOT NULL DEFAULT 0;
ALTER TABLE interfaces DROP COLUMN vrf;
UPDATE routes SET vrf_id = NULL;
DROP TABLE vrfs;
